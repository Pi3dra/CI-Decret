from decret import *
from selenium.common.exceptions import WebDriverException, NoSuchElementException
import re

DEBUG = True

def debug(string):
    if DEBUG:
        print(string)

class vuln_config:
    def __init__(self, version = None, timestamp = None, certainty = None):
        self.version = version
        self.timestamp = timestamp 
        self.certainty = certainty

    def to_string(self):
        return (f"version: {self.version}\n "
                f"timestamp: {self.timestamp}\n "
                f"certainty: {self.certainty}\n" #[bug,DSA,n-1,still_vulnerable]
                #how recent is the release + information source
                )

class cve:
    def __init__(self, package=None, release=None, fixed=None, advisories=None, bugids=[],vulnerable=[]):
        self.package = package
        self.release = release
        self.fixed = fixed
        self.vulnerable = vulnerable
        self.advisories = advisories
        self.bugids = bugids

    def to_string(self):
        vuln_version_strs = [ x.to_string() for x in self.vulnerable]
        vuln_version_strs = ''.join(vuln_version_strs)

        return (f"{self.package}:\n "
              f"release: {self.release}\n "
              f"fixed:\n  {self.fixed}\n "
              f"vulnerable:\n\n{vuln_version_strs}"
              f"advisories:\n  {self.advisories}\n "
              f"bugids:  {self.bugids} \n "
            )


def get_cve_tables_selenium(browser, args: argparse.Namespace):
    cve_id = f"CVE-{args.cve_number}"
    try:
        browser.get(f"https://security-tracker.debian.org/tracker/{cve_id}")
    except WebDriverException as exc:
        raise Exception("Selenium : Page not found. Wrong CVE number ?") from exc

    try:
        fixed_table = browser.find_element(By.XPATH, "/html/body/table[3]/tbody")

    except WebDriverException as exc:
        raise Exception(
                "Selenium : Table not found. Are you connected to internet ?"
        ) from exc
        
    #TODO: Add erros is package is marked as ITP or NOT-FOR-US
    try:
        info_table = browser.find_element(By.XPATH, "/html/body/table[2]/tbody")
    except WebDriverException as exc:
        raise Exception(
                "Selenium : Table not found. Are you connected to internet ? Or is the package ITP/RFP?"
        ) from exc

    info_table, fixed_table = clean_tables(info_table,fixed_table) 
    return info_table, fixed_table


def clean_tables(info_table, fixed_table):

    fixed_table = fixed_table.find_elements(By.XPATH, "./tr")
    fixed_table = [line.text.split() for line in fixed_table]

    debug("Output from security-tracker")
    debug(f"Fixed table \n: {fixed_table}")
    debug(f"Info table \n: {info_table.text}")

    for line in fixed_table:
        if line[3] == '(not':
            line[3] = '(not affected)'
            line.pop(4)

    for line in fixed_table:
        line.extend([""] * (7 - len(line)))
   
    #ordering urgency, dsa and bug columns
    for line in fixed_table:
        urgencys = ["unimportant", "medium", "low", "high"]
        dsa_dla = ""
        urgency = ""
        bug = ""
        
        for i in range(4, 7):
            if not line[i]:  
                continue
            if "DSA" in line[i] or "DLA" in line[i]:
                dsa_dla = line[i]
                line[i] = "" 
            elif any(urgency_val in line[i] for urgency_val in urgencys):
                urgency = line[i]
                line[i] = ""
            elif line[i].isdigit():
                bug = line[i]
                line[i] = ""
        
        if urgency:
            line[3] = urgency
        if dsa_dla:
            line[5] = dsa_dla
        if bug:
            line[6] = bug

  
    info_table = info_table.find_elements(By.XPATH, "./tr")
    info_table = [line.text.split() for line in info_table ]

    #remove header
    if len(info_table) > 0:
        info_table.pop(0)
    if len(fixed_table) >0:
        fixed_table.pop(0)

    #Clean PTS and merge (security) with previous column
    for row in info_table:
        i = 0
        while i < len(row):
            if "(PTS)" in row[i]:
                row.pop(i)
            elif "(security)" in row[i] and i > 0:
                row[i-1] = f"{row[i-1]} (security),"
                row.pop(i)
            else:
                i += 1

    #merge multiple releases into a single column
    for row in info_table:
        i = 0
        release_idx = []
        while i < len(row):
            is_release = any(release in row[i] for release in ["sid", "trixie"] + DEBIAN_RELEASES)
            if is_release:
                release_idx.append(i)
            if len(release_idx) >= 2:
                row[release_idx[0]] = row[release_idx[0]] + row[i]
                row.pop(i)
                release_idx.pop()
            i += 1

    #Add missing package names to all lines
    packagename = ""
    for i in range(0,len(info_table)):
        if len(info_table[i]) == 4:
            packagename = info_table[i][0]
        if len(info_table[i]) < 4:
            info_table[i].insert(0,packagename)

    debug(f"\nunfiltered output of fixed table: \n")
    for line_fixed in fixed_table:
        debug(f"{line_fixed}")
        assert len(line_fixed) == 7 , f"line: {line_fixed} is not of correct format"

    debug(f"\nunfiltered output of info table: \n")
    for line_info in info_table:
        debug(f"{line_info}")
        #assert len(line_info) == 4 , f"line: {line_info} is not of correct format"

    return info_table, fixed_table

def filter_tables(info_table, fixed_table):
    #The idea of filtering separately is to have all available data and 
    #make it ieasier for implementig other stuff
    #also for handling args like --release

    fixed_table = [
        line for line in fixed_table 
        #TODO: Implement support for (unstable)
        if (
            "(unstable)" not in line) and 
            "(not affected)" not in line and 
            any(release in line for release in DEBIAN_RELEASES)] 

    info_table = [ 
        line for line in info_table 
        if(
            "(security)" not in line and
            "vulnerable" in line and
            any(release in line for release in DEBIAN_RELEASES)
        )]

    return info_table, fixed_table


def convert_tables(info_table, fixed_table):
    convert_results = []

    for line in fixed_table:
        try:
            bug_id = int(line[6])
        except ValueError:
            bug_id = None

        config = cve(package=line[0],
                     release=line[2],
                     fixed=line[3],
                     advisories= None if line[5] == '' else line[5],
                     bugids= [] if not line[6]  else [(bug_id, False)])
        convert_results.append(config)

    #If there's a line here, it means the release concerned by this line is vulnerable
    #see: filter_table
    for line in info_table:
        vc = vuln_config(version=line[2],
                         certainty=10
                         )
        config = cve(package=line[0],
                     release=line[1],
                     vulnerable=[vc])
        convert_results.append(config) 
   
    for config in convert_results:
        debug(f"{config.to_string()}\n")

    return convert_results


def preceding_version_lookup(cve_details:cve):
    assert cve_details.fixed != None, (
            f"package: {cve_details.package} for {cve_details.release} has no fixed_version")

    url =  f"http://snapshot.debian.org/mr/package/{cve_details.package}/"
    response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
    known_versions = [x["version"] for x in response if "~bpo" not in x["version"]]

    if cve_details.fixed == "(unfixed)":
        vc = vuln_config(version = known_versions[0], certainty= 10)
        cve_details.vulnerable.append(vc)

    else:
        for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
            if version == cve_details.fixed:
                vc = vuln_config(version = prev_version, certainty= 5)
                break
    
    return cve_details

#TODO: Turn these into methods
def bug_version_lookup(browser, cve_details, args , check = False):
    if cve_details.bugids == []:
        raise Exception(f"package: {cve_details.package} for {cve_details.release} has no bugids")

    debug(cve_details.bugids)

    for bugid, used in cve_details.bugids:

        if bugid < 40000:
            print(f"The bugId : {bugid} might no longer be available")

        if not used:
            used = True #To prevent re-doing this
            url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={bugid}"
            try:
                browser.get(url)
                #Check if we find the CVE mentioned anywhere in the bug report 
                if check:
                    cve_fullname= f"CVE-{args.cve_number}"
                    debug(f"Checking if there's a DSA->bug->link"
                          f"{cve_fullname} in page: {cve_fullname in browser.page_source}"
                            )
                    if cve_fullname not in browser.page_source:
                        raise Exception("The bug linked to this cve through DSA doesn't seem to concern the current CVE")
            except WebDriverException as exc:
                raise Exception("Selenium : Page not found. Wrong bug number" ) from exc

            try:
                bug_info = browser.find_element(By.CLASS_NAME, "buginfo")
                p_tags = bug_info.find_elements(By.TAG_NAME, "p") 
                versions = [] 

                #This code seems really slow
                for p_tag in p_tags:
                    text = p_tag.text
                    if text.startswith("Found in version ") or text.startswith("Found in versions ")  :
                        version = text[len("Found in version "):].strip().split(", ")
                        versions.extend(version)
                debug(versions)

                #We treat cases where one bug concerns many versions
                for version in versions:
                    #fix_certainty, depends from check
                    vc = vuln_config( version = version, certainty = 10 if not check else 5)
                    cve_details.vulnerable.append(vc)
                if not versions:
                    raise Exception(f"bug { cve_details.bugids} has no 'Found in version' tag")


            except NoSuchElementException as exc:
                raise Exception("Selenium: 'buginfo' div or 'p' tag not found") from exc
            except WebDriverException as exc:
                raise Exception("Selenium: Error accessing page content") from exc
    
    

def dsa_version_lookup(browser,args, cve_details):
    if cve_details.advisories == None: 
        raise Exception (f"package: {cve_details.package} for {cve_details.release} has no DSA/DLA")

    if "DSA" in cve_details.advisories:
        url = f"https://www.debian.org/security/{cve_details.advisories}"
    else:
        url = f"https://www.debian.org/lts/security/{cve_details.advisories}"
    #the idea is to pass the found bug to the bug_version_lookup to do the rest; bug version bug_version_lookup 
    # might need to be broken down, to search a version given a bug, and then for a list of bugs(as DSAs have many)

    try:
        browser.get(url)
        pre_element = browser.find_element(By.TAG_NAME, "pre")
        advisory_text = pre_element.text
    except NoSuchElementException:
        raise Exception("Selenium: 'pre' tag not found on the page")
    except WebDriverException as exc:
        raise Exception("Selenium : Page not found. Wrong DSA number " ) from exc
    #Find CVE tags, might help to know if CVE is concerned
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_ids = re.findall(cve_pattern, advisory_text)
    if not cve_ids:
        raise Exception("No CVE IDs found in the security advisory")
   
    #Find Bug Ids
    bug_pattern = r'Debian Bug\s*:\s*([\d\s]+)'
    bug_match = re.search(bug_pattern, advisory_text)
    bug_ids = bug_match.group(1).strip().split() if bug_match else []
    bug_ids = [ (int(bugid),False) for bugid in bug_ids]
    if not bug_ids:
        raise Exception("No Debian Bug IDs found in the security advisory")

    #Now that we found the bugIds we try and find a version behind these bugIds
    cve_details.bugids.extend(bug_ids)
    bug_version_lookup(browser,cve_details,args,check=True)
    



def vulnerable_versions_lookup(browser, cve_list, args):
    for cve in cve_list:
        debug(f"Processing cve: \n\n {cve.to_string()}")

        #TODO: this would be cleaner using a chain of try withs

        try:
            bug_version_lookup(browser,cve,args)
        except Exception as e:
            print( f"Finding version through bugid failed with:\n{e}")

            if cve.advisory:
                print("\nattempting to find version using DSAs")
                try:
                    dsa_version_lookup(browser,args,cve)
                except Exception as e:
                    print( f"Finding version through DSAs failed with:\n{e}"
                            "\nattempting to find the preceding version of the fixed one")
                    preceding_version_lookup(cve)
            else:
                #TODO: Check if requests should also raise exceptions
                print("attempting the preceding version of the fixed one")
                preceding_version_lookup(cve)



    """
    GATHERING INFORMATION:
        for gathering the information on 
        https://security-tracker.debian.org/tracker/CVE-2019-9514

        We can use directly the website, or 
        use the JSON used in decret to build the top table
        and the /salsa/.../CVE list to build the bottom one

        For robustness might be interesting to merge the two methods
        as sometimes information is missing from certain sources and present in others

        This allows us to build a list of configuration descriptions using
        the cve class described on top, and later search for vulnerable configs

        NOTE: The search of vulnerable configs is solely done with selenium
        NOTE: maybe requests + beautifulsoup might be faster?
        

    FINDING VULNERABLE CONFIGS:

    If a (release,package) is considered still vulnerable from the first table of security-tracker
        register the version saying we are certain it works
    
    else try searching through BugIds
        if we find a version behind the bugId
            register it saying we are certain it works

    else if we don't find a version or there's no BugId 
        if there's a DSA/DLA then 
            try and deduce a bugId tied to the release (not sure how yet)
                using that bugId try and find a version

            if we find a version behind the bugId 
                register it saying we are almost certain it works
        
        else if there's no DSA or we don't find a version
            use default strategy and search for the version previous to the fixed_release
            and say we are not so certain


    We do this for each table entry and we choose the one we are most certain of working,
    like a recent release, with a package found through "reliable" methods


    """


if __name__ == "__main__":
    #TODO: turn lookup functions into methods
    #TODO: Figure out how to extensively test this thing
    try: 
        browser = prepare_browser()
        args = argparse.Namespace()
        args.cve_number = "2016-3714"

        info_table, fixed_table = get_cve_tables_selenium(browser,args)
        info_table, fixed_table = filter_tables(info_table, fixed_table)
        cve_list = convert_tables(info_table, fixed_table)
        vulnerable_versions_lookup(browser,cve_list,args)

        debug("\nResults: \n")
        for cve in cve_list:
            debug(f"{cve.to_string}\n")


    except FatalError as fatal_exc:
        print(fatal_exc, file = sys.stderr)
        sys.exit(1)

