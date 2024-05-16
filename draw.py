#!/usr/bin/env python3

"""
DrawMeATree, v1.0.

Description: Visualizes the result of a the Windbg command wt as two graphic trees:
                - a full tree with all the functions calls;
                - a filtered tree based on custom filters.

Author: Mathilde Venault
Copyright 2023 CrowdStrike, Inc.
Date Created: September, 2023

Python required version: 3.6
Dependencies:
- python libs: anytree, rich
- software: Graphviz (available at https://graphviz.org/download/)
Note: Make sure to add Graphviz to the PATH at the installation.

For usage instructions, run with --help.
"""

import argparse
import logging
import subprocess
import re
import sys

from pathlib import Path

from anytree import Node, RenderTree
from anytree.exporter import DotExporter
from rich.logging import RichHandler


# Global variable containing the list of unique MODULES_LIST
MODULES_LIST = []


def determine_node_att(node: Node) -> str:
    """Determine the attributes of a given node.

    Args:
        node (Node): a given node of a tree

    Returns:
        string: the attributes of a node including its color, shape and style.
    """
    colors = [
        "lightblue",
        "thistle",
        "wheat",
        "darkseagreen",
        "darksalmon",
        "papayawhip",
        "rosybrown",
        "lightcoral",
        "tan",
        "cadetblue",
        "plum",
    ]
    module_node = node.name.split("!")[0]

    for module in MODULES_LIST:
        if module_node == module:
            index = list(MODULES_LIST).index(module_node)
            if index >= len(colors):
                return "shape=box, style=filled, fillcolor = grey"

            return f"shape=box, style=filled, fillcolor = {colors[index]}"

    raise ValueError(f"Couldn't retrieve attribute of node: {module_node}.")


def adding_to_module_list(function_module: str) -> None:
    """Build a list of unique Windows module involved in the tree.

    Args:
        function_module (str): an entry of the tree within the format module!function_name
    """
    module_node = function_module.split("!")[0]

    if module_node:
        if module_node not in MODULES_LIST:
            MODULES_LIST.append(module_node)


def adding_to_tree(
    tree: Node, curr_node: Node, curr_lvl: int, index: int, function: str
) -> (Node, Node, int):
    """Process a given lines from the wt output and adds it to the tree.

    Args:
        my_tree (Tree): the tree to update
        curr_node (Node): the last node of the tree seen
        current_level (int): the last depth level seen
        index (int): the depth level of the entry to add to the tree
        function (str): the entry name to add to the tree within the format module!function_name

    Returns:
        my_tree (Tree): updated version of the tree
        curr_node (Node): the node just added to the tree
        current_level (int): the level of the node just added to the tree
    """

    if index == 0:
        if tree is None:  # If the very first line is being processed
            tree = Node(function)
            curr_node = tree
            curr_lvl = 0
        else:
            pass
    elif index == curr_lvl + 1:
        curr_node = Node(function, parent=curr_node)
        curr_lvl += 1
    # in case WinDbg skips  intermediary parent level
    elif index < curr_lvl:
        for i in range(curr_lvl - index):
            curr_node = curr_node.parent
        curr_lvl = index
    elif index == curr_lvl:
        curr_node = Node(function, parent=curr_node.parent)
    else:
        raise ValueError(
            f"Couldn't add entry {curr_lvl, function} to node {index, curr_node.name}."
        )

    return tree, curr_node, curr_lvl


def parse_input_file(wt_output_file: Path, filter_level: int) -> list:
    """Open the file containing wt output and parses relevant lines with a depth <= to filter level.

    Args:
        wt_output_file (Path): path of the file to parse
        filter_level (int): maximum depth of the line to parse

    Returns:
        list: parsed lines from wt_output_files, to add to tree
    """
    with open(wt_output_file, "r", encoding="utf-8") as wt_data:
        data = wt_data.readlines()

    parsed_lines = []
    for line in data:
        if re.search(r"\[  [0-" + str(filter_level) + "].*$", line):
            words = line.split()
            # Retreive function's name and depth
            index = int(words[3].replace("]", ""))
            function = words[4]
            parsed_lines.append([index, function])

            # Add the module to the list of known MODULES_LIST
            adding_to_module_list(function)

    if not parsed_lines:
        raise ValueError(f"Couldn't parse input file:{wt_output_file}.")

    return parsed_lines


def generate_tree(data: list, filters_list: list) -> Node:
    """Generate from a parsed wt output a tree filtering out function names matching the list of words given in the variable filters if any.

    Args:
        data (list): lines containing the wt output
        filters (list): (opt) function names to filter out from tree

    Returns:
        Node: tree resulting from the wt output
    """
    tree = None
    curr_node = None
    curr_lvl = 0
    next_index = None

    for entry in data:
        index = entry[0]
        function = entry[1]

        if filters_list is not None:
            if (
                next_index is not None and index > next_index
            ):  # if function is a child of a filtered node
                continue

            next_index = None
            is_valid_node = True
            for individual_filter in filters_list:
                if function.find(individual_filter) != -1:
                    is_valid_node = False
                    next_index = index  # Flag to skip lines until the parent node
                    break

            if is_valid_node is False:  # if passes the filtering step
                continue

        tree, curr_node, curr_lvl = adding_to_tree(
            tree, curr_node, curr_lvl, index, function
        )

    return tree


def display_console_tree(tree) -> None:
    """Display on the console the tree given in args.

    Args:
    tree (Tree): tree to display in the console
    """
    logging.info("Overview of the filtered tree:")

    for pre, _, node in RenderTree(tree):
        print(f"{pre}{node.name}")
    print("\n")


def generate_png(
    directory_path: Path, tree_type: str, tree: list, direction: str
) -> None:
    """Generate the png images of the resulting trees.

    Args:
        directory_path (Path): path to the directory in which the results should be generated
        tree (Tree): tree to convert into a .png
        tree_type (str): 'filtered_tree' or 'full_tree'
        direction (str): direction of the tree: 'LR' (default) or 'TB'
    """
    lines_seen = []
    tree_path = Path(directory_path, f"{tree_type}.png")

    # Build the dot tree
    dot_tree = DotExporter(
        tree,
        options=[f"rankdir={direction}"],
        nodenamefunc=(lambda node: node.name),
        nodeattrfunc=determine_node_att,
    )

    with open(f"{tree_type}.dot", "w+", encoding="utf-8") as dot_file:
        # Filter duplicates
        for line in dot_tree:
            if line not in lines_seen:
                dot_file.write(line)
                lines_seen.append(line)

    # Convert .dot tree to .png
    subprocess.run(
        f'dot {tree_type}.dot -T png -o "{tree_path}"', shell=False, check=True
    )


def parse_arguments() -> argparse.Namespace:
    """Parse, validate and procces arguments.

    Returns:
        Namespace: processed args
    """
    current_directory = Path.cwd()
    error_filters = ["Error", "mkstr"]
    char_filters = ["toupper", "tolower", "Unicode", "towlower", "towupper"]
    routine_filters = [
        "CriticalSection",
        "security_check",
        "Alloc",
        "Heap",
        "free",
        "operator",
        "LockExclusive",
    ]
    irrelevant_ops = [
        "memcpy",
        "memmove",
        "memset",
        "Close",
        "Rtlp",
        "Language",
        "initterm",
        "Fls",
    ]
    parser = argparse.ArgumentParser(
        description="Visualizes the result of a the Windbg command wt as a graphic tree.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "input_file", help="<Required> Input file with the result of wt command."
    )
    parser.add_argument(
        "-c",
        "--console",
        dest="console_mode",
        action="store_true",
        help="Display the resulting filtered tree in console.",
    )
    parser.add_argument(
        "-d",
        "--depth",
        dest="depth_level",
        metavar="1-9",
        default=9,
        type=int,
        choices=range(1, 10),
        help="Defines the depth level of filtering between 1 and 9. Default: 9.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="requested_dir",
        metavar="output_directory",
        help="Defines the repository to contain the resulting trees. Ex: C:\\Myresults",
        type=Path,
        default=current_directory,
    )
    parser.add_argument(
        "-t",
        "--tree",
        dest="direction",
        metavar="tree_direction",
        help="Defines the direction of the tree: LR (left to right) | TB (top to bottom).",
        choices=["LR", "TB"],
        default="LR",
    )
    parser.add_argument(
        "-f",
        "--filter",
        dest="filter_level",
        metavar="filter_level",
        help=f"""Defines the level of default filtering: light | medium (default) | high.
        1/ "light": {routine_filters + error_filters}
        2/ "medium": {routine_filters + error_filters + char_filters}
        3/ "high": {routine_filters + error_filters + char_filters + irrelevant_ops}""",
        choices=["light", "medium", "high"],
        default="medium",
    )
    parser.add_argument(
        "-a",
        "--addfilters",
        dest="filters_words",
        metavar="filters_words",
        nargs="+",
        help="Adds a list of custom filters. Ex: -a  cmp memcpy",
        default=[],
    )
    args = parser.parse_args()

    if not Path(args.input_file).exists():
        raise FileNotFoundError(f"Couldn't find the file: {args.input_file}.")

    # Process optional parameters
    if args.requested_dir is not current_directory:
        if Path(args.requested_dir).exists():
            args.requested_dir = Path(args.requested_dir).resolve()
        else:
            logging.warning(
                "[-] Unable to find directory: [magenta]%s[/].", args.requested_dir
            )
            args.requested_dir = current_directory
            logging.warning(
                "Generating trees instead in: [magenta]%s[/].", args.requested_dir
            )

    if args.filter_level == "light":
        args.filters_words.extend(routine_filters + error_filters)
    elif args.filter_level == "medium":
        args.filters_words.extend(routine_filters + error_filters + char_filters)
    elif args.filter_level == "high":
        args.filters_words.extend(
            routine_filters + error_filters + char_filters + irrelevant_ops
        )

    return args


if __name__ == "__main__":

    print(
        r"""
  ____                     __  __         _  _____
 |  _ \ _ __ __ ___      _|  \/  | ___   / \|_   _| __ ___  ___
 | | | | '__/ _` \ \ /\ / / |\/| |/ _ \ / _ \ | || '__/ _ \/ _ \
 | |_| | | | (_| |\ V  V /| |  | |  __// ___ \| || | |  __/  __/
 |____/|_|  \__,_| \_/\_/ |_|  |_|\___/_/   \_\_||_|  \___|\___|
 """
    )

    RETURN_CODE = 0
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(markup=True)],
    )
    logger = logging.getLogger("rich")

    try:
        p_args = parse_arguments()

        parameters = f"""> Processing wt result with the following parameters:
|_ Input file:          [magenta]{p_args.input_file}[/]
|_ Depth level:         {p_args.depth_level}
|_ Filter words:        {p_args.filters_words}
|_ Print in terminal:       {p_args.console_mode}
|_ Direction of trees:      [bright_cyan]{p_args.direction}[/]
|_ Export results in:       [magenta]{p_args.requested_dir}[/]

    """
        logger.info(parameters)

        wt_input = parse_input_file(p_args.input_file, p_args.depth_level)
        logger.info("> Parsing of wt output...  [green3]OK[/]")

        full_tree = generate_tree(wt_input, None)
        filtered_tree = generate_tree(wt_input, p_args.filters_words)
        logger.info("> Creation of the trees...     [green3]OK[/]")

        generate_png(p_args.requested_dir, "full_tree", full_tree, p_args.direction)
        generate_png(
            p_args.requested_dir, "filtered_tree", filtered_tree, p_args.direction
        )
        logger.info("> Generation of the pngs...    [green3]OK[/]")

        if p_args.console_mode is True:
            display_console_tree(filtered_tree)

        logging.info(
            "[+] [green3]Success![/] Trees have been generated in: \n[magenta]%s[/].",
            p_args.requested_dir,
        )

    except FileNotFoundError as e:
        RETURN_CODE = 1
        logging.exception("[-] Error: %s", e)
        logging.warning("[red]Please choose an existing file.[/]")

    except ValueError as e:
        RETURN_CODE = 1
        logging.exception("[-] Error: %s", e)
        logging.warning("[red]Please check the input file's format.[/]")

    except subprocess.CalledProcessError as e:
        RETURN_CODE = 1
        logging.exception("[-] Error executing dot:\n %s", e)
        logging.warning(
            "[red]Please verify Graphiz is installed and present in PATH.[/]"
        )

    finally:
        # Clean temporary files
        if Path("full_tree.dot").exists():
            Path.unlink(Path("full_tree.dot"))
        if Path("filtered_tree.dot").exists():
            Path.unlink(Path("filtered_tree.dot"))

    sys.exit(RETURN_CODE)
