"""
Software Name : decret (DEbian Cve REproducer Tool)
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023-2025 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Authors : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR, Mathieu BACOU,
Nicolas DEJON
Software description : A tool to reproduce vulnerability affecting Debian
It gathers details from the Debian metadata and exploits from exploit-db.com
in order to build and run a vulnerable Docker container to test and
illustrate security concepts.
"""

from typing import Tuple

import argparse
import os
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import jinja2

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException

DEBIAN_RELEASES = [
    "woody",
    "sarge",
    "etch",
    "lenny",
    "squeeze",
    "wheezy",
    "jessie",
    "stretch",
    "buster",
    "bullseye",
    "bookworm",
    "trixie",  # This one just helps find information easier
]


# The releases available here: http://ftp.debian.org/debian/ crash if the
# sources.list is overwriten to only use the snapshot, meanwhile those
# who are not here need to strictly use the snapshot if not they crash
AVAILABLE_ON_MAIN_SITE = DEBIAN_RELEASES[-5:]

LATEST_RELEASE = DEBIAN_RELEASES[-1]

DEFAULT_TIMEOUT = 10

DOCKER_SHARED_DIR = "/tmp/decret"

# makes testing easier:
# -Copies the mounted folder with exploits on the image
# -Avoids running the image interactively after build
RUNS_ON_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"


class FatalError(BaseException):
    pass


class CVENotFound(BaseException):
    pass


def arg_parsing(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--number",
        dest="cve_number",
        type=str,
        help="A CVE number to search (e.g.: 2022-38392)",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--release",
        dest="release",
        type=str,
        choices=DEBIAN_RELEASES,
        help="Debian Release name from 2005 to 2025",
        required=True,
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="dirname",
        type=str,
        help="Directory path for the CVE experiment",
        default="./default",
    )
    parser.add_argument(
        "--vulnerable-version",
        dest="vulnerable_version",
        type=str,
        help="Specify the vulnerable version number of the package",
    )
    parser.add_argument(
        "-p",
        "--package",
        dest="bin_package",
        type=str,
        help="Name of the binary package targeted.",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        help="Port forwarding between the Docker and the host",
    )
    parser.add_argument(
        "--host-port",
        dest="host_port",
        type=int,
        help="Set the host port in case of port forwarding (default is the --port value)",
    )
    parser.add_argument(
        "-s",
        "--selenium",
        dest="selenium",
        action="store_true",
        help="Activate the use of selenium (mandatory to download the exploit)",
    )
    parser.add_argument(
        "--do-not-use-sudo",
        dest="do_not_use_sudo",
        action="store_true",
        help="Do not use sudo to run docker commands",
    )
    parser.add_argument(
        "--only-create-dockerfile",
        dest="only_create_dockerfile",
        action="store_true",
        help="Do not build nor run the created docker",
    )
    parser.add_argument(
        "--dont-run",
        dest="dont_run",
        action="store_true",
        help="Build but don't run the created image",
    )
    parser.add_argument(
        "--cache-main-json-file",
        dest="cache_main_json_file",
        type=str,
        help="Path to load/save https://security-tracker.debian.org/tracker/data/json",
    )
    parser.add_argument(
        "--run-lines",
        dest="run_lines",
        nargs="*",
        help="Add RUN lines to execute commands to finalize the environment",
    )
    parser.add_argument(
        "--cmd-line",
        dest="cmd_line",
        type=str,
        help="Change the CMD line to specify the command to run by default in the container",
    )

    namespace = parser.parse_args(args)

    if re.match(r"^CVE-2\d{3}-(0\d{3}|[1-9]\d{3,})$", namespace.cve_number):
        namespace.cve_number = namespace.cve_number[4:]
    elif not re.match(r"^2\d{3}-(0\d{3}|[1-9]\d{3,})$", namespace.cve_number):
        parser.print_usage(sys.stderr)
        raise FatalError("Wrong CVE format.")

    return namespace


def check_program_is_present(progname, cmdline):
    try:
        subprocess.run(cmdline, check=True, shell=False, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError(
            f"{progname} does not seem to be installed. {cmdline} did not return 0."
        ) from exc


def check_requirements(args):
    check_program_is_present("Docker", ["docker", "-v"])
    if args.selenium:
        check_program_is_present("Firefox", ["firefox", "-v"])


def init_shared_directory(args):
    args.directory = Path(args.dirname)
    try:
        args.directory.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise FatalError(f"Error while creating {args.dirname}") from exc


def get_exploit(browser, args: argparse.Namespace):
    browser.get(f"https://www.exploit-db.com/search?cve={args.cve_number}")
    time.sleep(3)
    exploit_table = browser.find_element(By.ID, "exploits-table").find_element(
        By.XPATH, "./tbody"
    )

    i = 0
    urls = []
    for row in exploit_table.find_elements(By.XPATH, "./tr"):
        if row.text == "No data available in table":
            return []
        link_exploit = row.find_element(By.XPATH, "./td[2]/a").get_attribute("href")
        verified = bool(
            "check" in row.find_element(By.XPATH, "./td[4]/i").get_attribute("class")
        )

        exploit_filename = f"exploit_{i}"
        exploit_url_filename = f"exploit_{i}.url"
        if verified:
            exploit_filename += "_verified"
        exploit_path = args.directory / exploit_filename
        exploit_url_path = args.directory / exploit_url_filename

        headers = {"User-agent": "curl/7.74.0"}
        exploit = requests.get(link_exploit, headers=headers, timeout=DEFAULT_TIMEOUT)
        exploit_path.write_bytes(exploit.content)
        exploit_url_path.write_text(f"{link_exploit}\n")

        urls.append(link_exploit)
        i += 1
    return urls


def prepare_browser():
    options = webdriver.FirefoxOptions()
    options.add_argument("--headless")
    return webdriver.Firefox(options=options)


def search_in_table(release: str, info_table) -> Tuple[list[dict], list[str]]:
    results = []
    available_releases = []
    i = 0
    desired_release = False
    for row in info_table.find_elements(By.XPATH, "./tr"):
        if i == 0:
            i += 1
            continue
        data = row.text.split(" ")
        if "(unfixed)" in data:
            results.append(
                {
                    "src_package": data[0],
                    "release": "bullseye" if (data[2] == "(unstable)") else data[2],
                    "fixed_version": "(unfixed)",
                }
            )
        else:
            if release in data:
                desired_release = True
                src_package = data[0]
                release = data[2]
                fixed_version = data[3]
                results.append(
                    {
                        "src_package": src_package,
                        "release": release,
                        "fixed_version": fixed_version,
                    }
                )
            else:
                available_releases.append(data[2])
        i += 1

    if (
        desired_release
    ):  # If the desired release of Debian is present, we remove the unfixed release.
        results = [
            results[i] for i in range(len(results)) if results[i]["release"] == release
        ]
    return results, available_releases


def get_cve_details_from_selenium(browser, args: argparse.Namespace) -> list[dict]:
    cve_id = f"CVE-{args.cve_number}"
    try:
        browser.get(f"https://security-tracker.debian.org/tracker/{cve_id}")
    except WebDriverException as exc:
        raise Exception("Selenium : Page not found. Wrong CVE number ?") from exc

    try:
        info_table = browser.find_element(By.XPATH, "/html/body/table[3]/tbody")

    except WebDriverException:
        try:
            info_table = browser.find_element(By.XPATH, "/html/body/table[2]/tbody")
        except WebDriverException as exc:
            raise Exception(
                "Selenium : Table not found. Are you connected to internet ?"
            ) from exc

    results, available_releases = search_in_table(args.release, info_table)

    if not results:
        releases_string = ", ".join(available_releases)
        raise Exception(
            f"Vulnerability not found for Debian {args.release}. Try {releases_string}."
        )

    return results


def get_cve_details_from_json(args: argparse.Namespace) -> list[dict]:
    response = None
    if args.cache_main_json_file:
        json_cache_file = Path(args.cache_main_json_file)
        if json_cache_file.exists():
            json_content = json_cache_file.read_text(encoding="utf-8")
            response = json.loads(json_content)
    if not response:
        url = "https://security-tracker.debian.org/tracker/data/json"
        print(f"Fetching {url}")
        server_answer = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response = server_answer.json()
        if args.cache_main_json_file:
            json_cache_file = Path(args.cache_main_json_file)
            json_cache_file.write_bytes(server_answer.content)
            print(f"Debian tracker JSON saved at {args.cache_main_json_file}.")

    results = []

    cve_id = f"CVE-{args.cve_number}"
    for package_name, package_info in response.items():
        if cve_id not in package_info:
            continue

        cve_info = package_info[cve_id]
        if args.release not in cve_info["releases"]:
            continue

        if cve_info["releases"][args.release]["status"] == "open":
            fixed_version = "(unfixed)"
        else:
            fixed_version = cve_info["releases"][args.release]["fixed_version"]
        if fixed_version == "0":
            raise CVENotFound(
                f"Debian {args.release} was not affected by {cve_id}.\n"
                f"Try another release."
                f"(see https://security-tracker.debian.org/tracker/CVE-{args.cve_number})."
            )
        results.append(
            {
                "src_package": package_name,
                "release": args.release,
                "fixed_version": fixed_version,
            }
        )

    if not results:
        raise CVENotFound("No affected package found.")

    return results


def get_vuln_version(args: argparse.Namespace, cve_details: list[dict]) -> list[dict]:
    for item in cve_details:
        if args.vulnerable_version:
            item["vuln_version"] = args.vulnerable_version
            continue
        url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
        known_versions = [x["version"] for x in response if "~bpo" not in x["version"]]
        if item["fixed_version"] == "(unfixed)":
            item["vuln_version"] = known_versions[0]  # We select the latest version
        else:
            for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
                if version == item["fixed_version"]:
                    item["vuln_version"] = prev_version
                    break
        if not item["vuln_version"]:
            raise Exception("Vulnerable version of the packages not found.")
    return cve_details


def get_bin_names(cve_details: list[dict]) -> list[str]:
    bin_names = []
    for item in cve_details:
        # pylint: disable=line-too-long
        url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/{item['vuln_version']}/binpackages"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
        for res in response:
            bin_names.append(res["name"])

    return bin_names


def get_hash_and_bin_names(
    args: argparse.Namespace, cve_details: list[dict]
) -> list[dict]:
    i = 0
    for item in cve_details:
        try:
            # pylint: disable=line-too-long
            url = f"http://snapshot.debian.org/mr/binary/{item['src_package']}/{item['vuln_version']}/binfiles"
            response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
            for res in response:
                if res["architecture"] == "amd64" or res["architecture"] == "all":
                    item["hash"] = res["hash"]
                    break
            item["bin_name"] = [item["src_package"]]
        # pylint: disable=broad-except
        except Exception:
            try:
                # We get the hash from the src files, but we also collect the
                # binary packages names associated for the Dockerfile.
                # pylint: disable=line-too-long
                url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/{item['vuln_version']}/srcfiles"
                response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
                item["hash"] = response[-1]["hash"]
                item["bin_name"] = get_bin_names(cve_details)

            except Exception as exc:
                raise Exception(
                    "Couldn't find the source files for the Linux packages."
                ) from exc

        if item["src_package"] == "linux":
            item["bin_name"] = []

        if args.bin_package:
            if args.bin_package in item["bin_name"]:
                item["bin_name"] = [args.bin_package]
            else:
                raise Exception(
                    "Non existing binary package provided. Check your '-p' option."
                )
        i += 1
    return cve_details


def get_snapshot(cve_details: list[dict]):
    snapshot_id = []
    for item in cve_details:
        value = item.get("hash")
        if value is None:
            print(f"Not found in '{item}'")
        else:
            url = f"http://snapshot.debian.org/mr/file/{item['hash']}/info"

            response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"][-1]
            snapshot_id.append(response["first_seen"])

    if not snapshot_id:
        raise Exception("Snapshot id not found.")

    return snapshot_id


def write_cmdline(args: argparse.Namespace):
    cmdline_path = args.directory / "cmdline"
    with cmdline_path.open("w", encoding="utf-8") as cmdline_file:
        args_to_write = []
        for arg in sys.argv:
            if " " in arg:
                arg = arg.replace(r"\\", r"\\")
                arg = arg.replace(r'"', r"\"")
                arg = f'"{arg}"'
            args_to_write.append(arg)
        cmdline_file.write(" ".join(args_to_write))
        cmdline_file.write("\n")


def prepare_sources(snapshot_id: str, vuln_fixed: bool):
    options = (
        "[check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes]"
    )
    url = f"http://snapshot.debian.org/archive/debian/{snapshot_id}/"
    if vuln_fixed:
        release = ["testing", "stable", "unstable"]
        return [f"deb {options} {url} {rel} main" for rel in release]
    return []


# pylint: disable=too-many-locals
def write_dockerfile(args: argparse.Namespace, cve_details, source_lines: list[str]):
    target_dockerfile = args.directory / "Dockerfile"
    decret_rootpath = Path(__file__).resolve().parent
    src_template = decret_rootpath / "Dockerfile.template"
    template_content = src_template.read_text()
    template = jinja2.Environment().from_string(template_content)

    if args.release in DEBIAN_RELEASES[:7]:
        apt_flag = "--force-yes"
    else:
        apt_flag = "--allow-unauthenticated --allow-downgrades"

    default_packages = " ".join(["aptitude", "nano", "adduser"])
    binary_packages = []
    for item in cve_details:
        for bin_name in item["bin_name"]:
            bin_name_and_version = [bin_name + f"={item['vuln_version']}"]
            binary_packages.extend(bin_name_and_version)

    # Old reseases should only use the snapshot sources
    clear_sources = args.release not in AVAILABLE_ON_MAIN_SITE

    content = template.render(
        clear_sources=clear_sources,
        debian_release=args.release,
        source_lines=source_lines,
        apt_flag=apt_flag,
        default_packages=default_packages,
        package_name=" ".join(binary_packages),
        run_lines=args.run_lines,
        cmd_line=args.cmd_line,
        copy_exploits=RUNS_ON_GITHUB_ACTIONS,
    )
    target_dockerfile.write_text(content)


def build_docker(args):
    print("Building the Docker image.")
    docker_image_name = f"{args.release}/cve-{args.cve_number}"

    if args.do_not_use_sudo:
        build_cmd = []
    else:
        build_cmd = ["sudo"]

    build_cmd.extend(["PROGRESS_NO_TRUNC=1"])
    build_cmd.extend(["docker", "build"])
    build_cmd.extend(["--progress", "plain", "--no-cache"])
    build_cmd.extend(["-t", docker_image_name])
    build_cmd.append(args.dirname)

    try:
        subprocess.run(build_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError("Error while building the container") from exc


def run_docker(args):
    docker_image_name = f"{args.release}/cve-{args.cve_number}"
    print(f"Running the Docker. The shared directory is '{DOCKER_SHARED_DIR}'.")

    if args.do_not_use_sudo:
        run_cmd = []
    else:
        run_cmd = ["sudo"]
    run_cmd.extend(["docker", "run", "--privileged", "-it", "--rm"])
    run_cmd.extend(["-v", f"{args.directory.absolute()}:{DOCKER_SHARED_DIR}"])
    run_cmd.extend(["-h", f"cve-{args.cve_number}"])
    run_cmd.extend(["--name", f"cve-{args.cve_number}"])
    if args.port:
        if args.host_port:
            run_cmd.extend(["-p" f"{args.host_port}:{args.port}"])
        else:
            run_cmd.extend(["-p" f"{args.port}:{args.port}"])
    run_cmd.append(docker_image_name)

    try:
        subprocess.run(run_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError("Error while running the container") from exc


def init_decret():  # pragma: no cover
    # First handle the parameters
    args = arg_parsing()
    check_requirements(args)
    init_shared_directory(args)

    browser = None
    # Initialize the selenium browser
    if args.selenium:
        try:
            browser = prepare_browser()
        except WebDriverException as exc:
            print(
                f"Warning: could not initialize selenium properly: {exc}\n"
                "Deactivating --selenium and trying to continue",
                file=sys.stderr,
            )
            browser = None
            args.selenium = None

    return args, browser


def main():  # pragma: no cover
    args, browser = init_decret()

    # Then get the details for the given CVE
    try:
        # We try to get the details by the Debian JSON
        cve_details = get_cve_details_from_json(args)
    except CVENotFound as exc:
        # We try Selenium when the CVE is not in the Tracker JSON
        if not browser:
            raise FatalError(
                "Can't get the details for CVE. Please consider using --selenium."
            ) from exc

        try:
            cve_details = get_cve_details_from_selenium(browser, args)
        except Exception as selenium_exc:
            raise FatalError(
                "Error while retrieving CVE details using Selenium"
            ) from selenium_exc

    # vuln_fixed is False if (unfixed) in cve_details
    vuln_fixed = not any(item["fixed_version"] == "(unfixed)" for item in cve_details)
    print(f"CVE details fetched.\n {cve_details}\n\n")

    print("Getting the vulnerable version.")
    cve_details = get_vuln_version(args, cve_details)
    print(f"vulnerable version : {cve_details[0]['vuln_version']}\n\n")

    print("Getting the hash of the package")
    cve_details = get_hash_and_bin_names(args, cve_details)
    print(f"Source package hash : {cve_details[0]['hash']}\n\n")

    # We keep the oldest snapshot possibility
    snapshot_id = min(get_snapshot(cve_details))
    if browser:
        try:
            # Get the exploits from https://www.exploit-db.com/
            exploit_urls = get_exploit(browser, args)
            n_exploits = len(exploit_urls)
            print(f"PoC: Found {n_exploits} exploits")
            for url in exploit_urls:
                print(f"      {url}")
        except WebDriverException as exc:
            print(f"Warning: could not fetch exploits properly: {exc}", file=sys.stderr)
        finally:
            browser.quit()

    source_lines = prepare_sources(snapshot_id, vuln_fixed)
    if not vuln_fixed:
        print(f"\n\nVulnerability unfixed. Using a {LATEST_RELEASE} container.\n\n")
        args.release = LATEST_RELEASE

    write_dockerfile(args, cve_details, source_lines)
    write_cmdline(args)
    if args.only_create_dockerfile:
        print("My work here is done.")
        return
    build_docker(args)
    if args.dont_run or RUNS_ON_GITHUB_ACTIONS:
        print("My work here is done.")
        return

    run_docker(args)
