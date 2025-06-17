import argparse
import os
import re
import pandas as pd
from bs4 import BeautifulSoup, Tag
from requests.exceptions import RequestException
from decret.decret import (
    requests,
    DEFAULT_TIMEOUT,
    DEBIAN_RELEASES,
    FatalError,
    CVENotFound,
    Path,
    sys,
)


DEBUG = False


class SearchError(BaseException):
    pass


def debug(string):
    if DEBUG:
        print(string)


class VulnerableConfig:
    def __init__(self, version=None, timestamp=None, method=None):
        self.version = version
        self.timestamp = timestamp
        self.method = method

    def to_string(self):
        return (
            f"  version: {self.version}\n "
            f"   timestamp: {self.timestamp}\n "
            f"   method: {self.method}\n"  # [bug,DSA,n-1,still_vulnerable]
        )


class Cve:
    def __init__(
        self,
        package=None,
        release=None,
        fixed=None,
        advisory=None,
        bugids=None,
        vulnerable=None,
    ):
        self.package = package
        self.release = release
        self.fixed = fixed
        self.vulnerable = vulnerable
        self.advisory = advisory
        self.bugids = bugids

    def to_string(self):
        vuln_version_strs = (
            "\n  " + "\n  ".join(x.to_string() for x in self.vulnerable)
            if self.vulnerable
            else "  None"
        )

        return (
            f"{self.package}:\n "
            f"release: {self.release}\n "
            f"fixed:\n  {self.fixed}\n "
            f"vulnerable:\n{vuln_version_strs}"
            f"advisory:\n  {self.advisory}\n "
            f"bugids:  {self.bugids} \n "
        )

    def init_vulnerable(self):
        if self.vulnerable is None:
            self.vulnerable = []

    def preceding_version_lookup(self):
        self.init_vulnerable()
        if self.fixed is None or self.vulnerable is None:
            raise SearchError(
                f"package: {self.package} for {self.release} has no fixed_version"
            )

        url = f"http://snapshot.debian.org/mr/package/{self.package}/"

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            response = response.json()
        except RequestException as exc:
            raise SearchError(f"snapshot.debian.org request failed: {exc}") from exc
        except ValueError as exc:
            raise SearchError("Snapshot response is not valid JSON") from exc
        if "result" not in response or not isinstance(response["result"], list):
            raise SearchError(f"Unexpected payload shape: {response!r}")

        known_versions = [
            x["version"] for x in response["result"] if "~bpo" not in x["version"]
        ]

        if self.fixed == "(unfixed)":
            vulnerable_config = VulnerableConfig(
                version=known_versions[0], method="Vulnerable"
            )
            self.vulnerable.append(vulnerable_config)
        else:
            found = False
            for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
                if version == self.fixed:
                    found = True
                    vulnerable_config = VulnerableConfig(
                        version=prev_version, method="N-1"
                    )
                    self.vulnerable.append(vulnerable_config)
                    break
            if not found:
                raise CVENotFound("Unable to find the preceding version")

        return self

    # This could be cleaner with an iterator handling the bugids
    def bug_version_lookup(self, args, check=False):
        self.init_vulnerable()

        if self.bugids is None or self.vulnerable is None:
            raise SearchError(
                f"package {self.package} for {self.release} has no bugids"
            )

        for i, (bugid, used) in enumerate(self.bugids):
            if bugid < 40000:
                print(
                    f"The bugId : {bugid} might no longer be available, triying anyways"
                )

            if not used:
                self.bugids[i] = (bugid, True)
                url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={bugid}"
                try:
                    response = requests.get(url, timeout=DEFAULT_TIMEOUT)
                    response.raise_for_status()
                    content = response.text

                    # Check if we find the CVE mentioned anywhere in the bug report
                    if check:
                        cve_fullname = f"CVE-{args.cve_number}"
                        debug(
                            f"Checking if there's a DSA->bug->link\n"
                            f"{cve_fullname} in page: {cve_fullname in content}"
                        )
                        if cve_fullname not in browser.page_source:
                            raise CVENotFound(
                                "The bug linked to this cve through"
                                "DSA doesn't seem to concern the current CVE"
                            )
                    soup = BeautifulSoup(content, "html.parser")
                    bug_info = soup.find("div", class_="buginfo")
                    if not bug_info or not isinstance(bug_info, Tag):
                        raise CVENotFound(
                            f"Could not find valid buginfo div for bug {bugid}"
                        )

                    versions = []

                    for p_tag in bug_info.find_all("p"):
                        text = p_tag.get_text(strip=True)
                        if text.startswith(("Found in version ", "Found in versions ")):
                            version = (
                                text[len("Found in version ") :].strip().split(", ")
                            )
                            versions.extend(version)
                    debug(versions)

                    # We treat cases where one bug concerns many versions
                    # TODO, Handle cases where the packagename is prepended to the version
                    for version in versions:
                        vulnerable_config = VulnerableConfig(
                            version=version, method="Bug" if not check else "DSA"
                        )
                        self.vulnerable.append(vulnerable_config)
                    if not versions:
                        raise CVENotFound(
                            f"bug { self.bugids} has no 'Found in version' tag"
                        )

                except RequestException as exc:
                    raise SearchError("requests: Error accesing bug report") from exc

    def dsa_version_lookup(self, args):
        # TODO: Investigate, some old DSAs are no longer available? CVE-2002-1051
        self.init_vulnerable()
        if self.bugids is None:
            self.bugids = []

        if self.advisory is None or self.vulnerable is not None:
            raise SearchError(
                f"package: {self.package} for {self.release} has no DSA/DLA"
            )

        url = (
            f"https://www.debian.org/"
            f"{'lts/' if 'DSA' in self.advisory else ''}"
            "security/{self.advisory}"
        )

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            pre_element = soup.find("pre")
            if not pre_element or not isinstance(pre_element, Tag):
                raise CVENotFound("requests: 'pre' tag not found on the page")
            advisory_text = pre_element.get_text(strip=True)

        except RequestException as exc:
            raise SearchError("Requests: Error accesing advisory") from exc

        # Find Bug Ids
        bug_pattern = r"Debian Bug\s*:\s*([\d\s]+)"
        bug_match = re.search(bug_pattern, advisory_text)
        bug_ids = bug_match.group(1).strip().split() if bug_match else []
        bug_ids = [(int(bugid), False) for bugid in bug_ids]
        if not bug_ids:
            raise CVENotFound("No Debian Bug IDs found in the security advisory")

        # Now that we found the bugIds we try and find a version behind these bugIds
        self.bugids.extend(bug_ids)
        self.bug_version_lookup(args, check=True)

    def vulnerable_versions_lookup(self, args):
        try:
            self.bug_version_lookup(args)
        except (SearchError, CVENotFound) as error:
            debug(f"finding vulnerable version for: {self.package},{self.release}")
            debug(f"Finding version through bugid failed with:\n\t{error}")
            if self.advisory:
                debug("\tattempting to find version using DSAs")
                try:
                    self.dsa_version_lookup(args)
                except (SearchError, CVENotFound) as error:
                    debug(
                        f"\t\tFinding version through DSAs failed with:\n\t\t\t{error}"
                        "\t\t\tattempting to find the preceding version of the fixed one"
                    )
                    try:
                        self.preceding_version_lookup()
                    except (SearchError, CVENotFound) as _:
                        debug(
                            f"\t\t\t\tThis package: {self.package} is currently vulnerable"
                        )
            else:
                debug("\tattempting to find the preceding version of the fixed one")
                try:
                    self.preceding_version_lookup()
                except (SearchError, CVENotFound):
                    debug(f"\t\tthis package: {self.package} is currently vulnerable")


def get_cve_tables(args: argparse.Namespace):
    url = f"https://security-tracker.debian.org/tracker/CVE-{args.cve_number}"
    fixed_table = None
    info_table = None
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        header_info = ["Source Package", "Release", "Version", "Status"]
        header_fixed = [
            "Package",
            "Type",
            "Release",
            "Fixed Version",
            "Urgency",
            "Origin",
            "Debian Bugs",
        ]

        info_tables = soup.find_all("table")  # Get all table tags
        for elt in info_tables:
            if info_tables is not None and isinstance(elt, Tag):
                header = [column.get_text() for column in elt.find_all("th")]
                if header == header_info:
                    info_table = elt
                if header == header_fixed:
                    fixed_table = elt

        if info_table is None and fixed_table is None:
            raise CVENotFound(
                "Decret didn't find any tables on the security tracker site"
            )

        info_table, fixed_table = clean_tables(info_table, fixed_table)
        info_table, fixed_table = filter_tables(info_table, fixed_table)

        if info_table is None and fixed_table is None:
            raise CVENotFound(
                "CVE is either ITP,NOT-FOR-US,REJECTED, or it doesn't affect any debian release"
            )
    except:
        print("TODO")

    return info_table, fixed_table


def clean_tables(info_table, fixed_table):
    if fixed_table is not None:
        fixed_table = list(fixed_table.find_all("td"))
        fixed_table = [line.get_text() for line in fixed_table]
        fixed_table = [fixed_table[i : i + 7] for i in range(0, len(fixed_table), 7)]
    else:
        fixed_table = []

    if info_table is not None:
        info_table = list(info_table.find_all("td"))
        info_table = [line.get_text() for line in info_table]
        info_table = [info_table[i : i + 4] for i in range(0, len(info_table), 4)]

    else:
        info_table = []

    current_package = ""
    for line in info_table:
        if line[0] != "":
            line[0] = "".join(line[0].split(" (PTS)"))
            current_package = line[0]
        elif line[0] == "":
            line[0] = current_package

    return info_table, fixed_table


def filter_tables(info_table, fixed_table):
    # The idea of filtering separately is to have all available data and
    # make it easier for implementig other stuff
    # also for handling args like --release
    fixed_table = [
        line
        for line in fixed_table
        # TODO: Implement support for (unstable)
        if "(not affected)" not in line and
        # This line might not be useful
        any(release in line for release in DEBIAN_RELEASES)
    ]

    info_table = [
        line
        for line in info_table
        if (
            "(security)" not in line
            and "vulnerable" in line
            and any(release in line for release in DEBIAN_RELEASES)
        )
    ]

    return info_table, fixed_table


def convert_tables(info_table, fixed_table):
    convert_results = []

    for line in fixed_table:
        try:
            bug_id = int(line[6])
        except ValueError:
            bug_id = None

        config = Cve(
            package=line[0],
            release=line[2],
            fixed=line[3],
            advisory=None if line[5] == "" else line[5],
            bugids=None if bug_id is None else [(bug_id, False)],
            vulnerable=[],
        )
        convert_results.append(config)

    # If there's a line here, it means the release concerned by this line is vulnerable
    # see: filter_table
    for line in info_table:
        vulnerable_config = VulnerableConfig(version=line[2], method="vulnerable")
        config2 = Cve(package=line[0], release=line[1], vulnerable=[vulnerable_config])
        convert_results.append(config2)

    for config in convert_results:
        debug(f"{config.to_string()}\n")

    return convert_results


def versions_lookup(cve_list, args):
    # might be smart to use flags to filter which method to use
    for cve in cve_list:
        cve.vulnerable_versions_lookup(args)


def download_db():
    # TODO: Try and cache this!
    project_id = "40927511"  # Project ID for exploit-db
    file_path = "files_exploits.csv"
    destination_path = "cached-files/files_exploits.csv"

    url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{file_path}/raw?ref=main"
    print(url)

    response = requests.get(url,timeout=DEFAULT_TIMEOUT)

    if response.status_code == 200:
        os.makedirs("cached-files", exist_ok=True)
        with open(destination_path, "wb") as file:
            file.write(response.content)
    else:
        print(f"Failed to download file: {response.status_code} - {response.text}")


def get_exploit(args):
    data = pd.read_csv("cached-files/files_exploits.csv")
    data = data[["id", "file", "verified", "codes", "tags", "aliases"]]
    cve_id = f"CVE-{args.cve_number}"
    # quel bonheur
    data = data[
        data["codes"].str.contains(cve_id, na=False)
        | data["tags"].str.contains(cve_id, na=False)
        | data["aliases"].str.contains(cve_id, na=False)
    ]
    data = list(zip(data["id"], data["file"], data["verified"]))

    output_dir = Path(args.directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    for i, (id, path, verified) in enumerate(data):
        # Building url
        project_id = "40927511"
        url = (
            f"https://gitlab.com/api/v4/projects/{project_id}"
            f"/repository/files/{path.replace('/', '%2F')}/raw?ref=main"
        )

        # Building path
        file_extension = os.path.splitext(path)[1]
        exploit_filename = f"exploit_{i}_{id}"
        if verified:
            exploit_filename += "_verified"
        exploit_path = output_dir / Path(exploit_filename + file_extension)

        # Fetching exploits
        response = requests.get(url,timeout = DEFAULT_TIMEOUT)
        if response.status_code == 200:
            os.makedirs("cached-files", exist_ok=True)
            with open(exploit_path, "wb") as file:
                file.write(response.content)
        else:
            print(f"Failed to download file: {response.status_code} - {response.text}")


if __name__ == "__main__":

    # TODO: find a way to get_exploit with requests instead of selenium
    try:
        args = argparse.Namespace()
        args.cve_number = "2016-3714"
        args.directory = "hey_listen!"

        """

        info_table, fixed_table = get_cve_tables(args)
        cve_list = convert_tables(info_table, fixed_table)
        versions_lookup(cve_list, args)

        print("\nResults: \n")
        for cve in cve_list:
            print(f"{cve.to_string()}\n")
        """
        download_db()
        get_exploit(args)

    except FatalError as fatal_exc:
        print(fatal_exc, file=sys.stderr)
        sys.exit(1)
