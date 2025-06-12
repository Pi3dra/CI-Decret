from decret.decret import * 
from selenium.common.exceptions import WebDriverException, NoSuchElementException
import argparse
import re

DEBUG = False

def debug(string):
    if DEBUG:
        print(string)

class vuln_config:
    def __init__(self, version = None, timestamp = None, method = None):
        self.version = version
        self.timestamp = timestamp 
        self.method = method

    def to_string(self):
        return (f"  version: {self.version}\n "
                f"   timestamp: {self.timestamp}\n "
                f"   method: {self.method}\n" #[bug,DSA,n-1,still_vulnerable]
                )

class cve:
    def __init__(self, package=None, release=None, fixed=None, advisory=None, bugids=[],vulnerable=[]):
        self.package = package
        self.release = release
        self.fixed = fixed
        self.vulnerable = vulnerable
        self.advisory = advisory
        self.bugids = bugids

    def to_string(self):
        vuln_version_strs = [ x.to_string() for x in self.vulnerable]
        vuln_version_strs = ''.join(vuln_version_strs)

        return (f"{self.package}:\n "
              f"release: {self.release}\n "
              f"fixed:\n  {self.fixed}\n "
              f"vulnerable:\n{vuln_version_strs}"
              f"advisory:\n  {self.advisory}\n "
              f"bugids:  {self.bugids} \n "
            )


    def preceding_version_lookup(self):
        assert self.fixed != None, (
            f"package: {self.package} for {self.release} has no fixed_version")

        #TODO: Problem, some bug reports "Found in version" are formatted like so:
        # packagename/version instead of just version, which should cause a bug
        url =  f"http://snapshot.debian.org/mr/package/{self.package}/"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
        known_versions = [x["version"] for x in response if "~bpo" not in x["version"]]
        if self.fixed == "(unfixed)":
            vc = vuln_config(version = known_versions[0], method = "Vulnerable")
            self.vulnerable.append(vc)
        else:
            for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
                if version == self.fixed:
                    vc = vuln_config(version = prev_version, method = "N-1")
                    self.vulnerable.append(vc)
                    break
    
        return self


    #This could be cleaner with an iterator handling the bugids
    def bug_version_lookup(self,browser, args , check = False):
        if self.bugids == []:
            raise Exception(f"package {self.package} for {self.release} has no bugids")

        for bugid, used in self.bugids:
            if bugid < 40000:
                print(f"The bugId : {bugid} might no longer be available")

            #TODO: This is not propely working
            if not used:
                used = True #To prevent re-doing this
                url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={bugid}"
                try:
                    browser.get(url)
                    
                    #Check if we find the CVE mentioned anywhere in the bug report 
                    if check:
                        cve_fullname= f"CVE-{args.cve_number}"
                        debug(f"Checking if there's a DSA->bug->link\n"
                              f"{cve_fullname} in page: {cve_fullname in browser.page_source}"
                                )
                        if cve_fullname not in browser.page_source:
                            raise Exception("The bug linked to this cve through"
                                            "DSA doesn't seem to concern the current CVE")
                    bug_info = browser.find_element(By.CLASS_NAME, "buginfo")
                    p_tags = bug_info.find_elements(By.TAG_NAME, "p") 
                    versions = [] 

                    #This code seems really slow
                    for p_tag in p_tags:
                        text = p_tag.text
                        if text.startswith(("Found in version ","Found in versions ")): 
                            version = text[len("Found in version "):].strip().split(", ")
                            versions.extend(version)
                    debug(versions)

                    #We treat cases where one bug concerns many versions
                    for version in versions:
                        vc = vuln_config( version = version, method = "Bug" if not check else "DSA")
                        self.vulnerable.append(vc)
                    if not versions:
                        raise Exception(f"bug { self.bugids} has no 'Found in version' tag")


                except NoSuchElementException as exc:
                    raise Exception("Selenium: 'buginfo' div or 'p' tag not found") from exc
                except WebDriverException as exc:
                    raise Exception("Selenium: Error accessing page") from exc



    def dsa_version_lookup(self,browser,args):
        #TODO: Investigate, some old DSAs are no longer available? CVE-2002-1051
        if self.advisory == None: 
            raise Exception (f"package: {self.package} for {self.release} has no DSA/DLA")

        url = (f"https://www.debian.org/"
               f"{'lts/' if 'DSA' in self.advisory else ''}"
               "security/{self.advisory}")

        try:
            browser.get(url)
            pre_element = browser.find_element(By.TAG_NAME, "pre")
            advisory_text = pre_element.text
        except NoSuchElementException:
            raise Exception("Selenium: 'pre' tag not found on the page")
        except WebDriverException as exc:
            raise Exception("Selenium : Page not found. Wrong DSA number " ) from exc
   
        #Find Bug Ids
        bug_pattern = r'Debian Bug\s*:\s*([\d\s]+)'
        bug_match = re.search(bug_pattern, advisory_text)
        bug_ids = bug_match.group(1).strip().split() if bug_match else []
        bug_ids = [ (int(bugid),False) for bugid in bug_ids]
        if not bug_ids:
            raise Exception("No Debian Bug IDs found in the security advisory")

        #Now that we found the bugIds we try and find a version behind these bugIds
        self.bugids.extend(bug_ids)
        self.bug_version_lookup(browser,args,check=True)
    

    def vulnerable_versions_lookup(self,browser, args):
        try:
            self.bug_version_lookup(browser,args)
        except Exception as e:
            debug(f"finding vulnerable version for: {self.package},{self.release}")
            debug(f"Finding version through bugid failed with:\n\t{e}")
            if self.advisory:
                debug("\tattempting to find version using DSAs")
                try:
                    self.dsa_version_lookup(browser,args)
                except Exception as e:
                    debug( f"\t\tFinding version through DSAs failed with:\n\t\t\t{e}"
                            "\t\t\tattempting to find the preceding version of the fixed one")
                    try:
                        self.preceding_version_lookup()
                    except Exception as e:
                        debug(f"\t\t\t\tThis package: {self.package} is currently vulnerable")
            else:
                #TODO: Check if requests should also raise exceptions
                debug("\tattempting to find the preceding version of the fixed one")
                try:
                    self.preceding_version_lookup()
                except:
                    debug(f"\t\tthis package: {self.package} is currently vulnerable")


 
def get_cve_tables_selenium(browser, args: argparse.Namespace):
    #TODO: Maybe this could be cleaner?
    #TODO: Improve Debugging
    cve_id = f"CVE-{args.cve_number}"
    info_table = None 
    fixed_table = None 

    try:
        browser.get(f"https://security-tracker.debian.org/tracker/{cve_id}")
        
        #Checking tables are present
        p_tags = browser.find_elements(By.TAG_NAME, "p") 
        p_tags = [s.text for s in p_tags]
        st1 = "The table below lists information on source packages."
        st2 = "The information below is based on the following data on fixed versions."
        has_fixed_table = any(st2 in s for s in p_tags)
        has_info_table = any(st1 in s for s in p_tags)
        indices = {
                "info": 2 if has_info_table else None,
                "fixed": 3 if has_info_table and has_fixed_table else 2 if has_fixed_table
                else None
        }
        
        if has_info_table: 
            info_table = browser.find_element(By.XPATH, f"/html/body/table[{indices['info']}]/tbody")
            
        if has_fixed_table:
            fixed_table = browser.find_element(By.XPATH, f"/html/body/table[{indices['fixed']}]/tbody")
            if "ITP" in fixed_table.text:
                raise Exception("CVE is ITP, this is not replicable")

        if not fixed_table and not info_table:
            raise Exception("No tables found")
            
    except WebDriverException as exc:
        raise Exception(
                "Selenium : Table not found. Are you connected to internet ? Or is the package ITP/RFP?"
        ) from exc
    

    debug("Raw Info table and Fixed table")
    if info_table is not None:
        for line in info_table.find_elements(By.TAG_NAME, "tr"):  # Iterate over table rows
            debug(line.text)
    else:
        debug("Info table not found")

    if fixed_table is not None:
        for line in fixed_table.find_elements(By.TAG_NAME, "tr"):  # Iterate over table rows
            debug(line.text)
    else:
        debug("Fixed table not found")
    

    info_table, fixed_table = clean_tables(info_table,fixed_table) 
 
    return info_table, fixed_table


def clean_tables(info_table, fixed_table):
    
    if fixed_table != None:
        fixed_table = fixed_table.find_elements(By.XPATH, "./tr")
        fixed_table = [line.text.split() for line in fixed_table]
    else:
        fixed_table = []

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
            line[4] = urgency
        if dsa_dla:
            line[5] = dsa_dla
        if bug:
            line[6] = bug

    if info_table != None: 
        info_table = info_table.find_elements(By.XPATH, "./tr")
        info_table = [line.text.split() for line in info_table ]
    else:
        info_table = []
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

   
    debug("Clean Info table and Fixed table")
    for line in info_table:
        debug(line)
    for line in fixed_table:
        debug(line)
    

    return info_table, fixed_table

def filter_tables(info_table, fixed_table):
    #The idea of filtering separately is to have all available data and 
    #make it easier for implementig other stuff
    #also for handling args like --release

    fixed_table = [
        line for line in fixed_table 
        #TODO: Implement support for (unstable)
        if  #"(unstable)" not in line) and 
            "(not affected)" not in line and 
            any(release in line for release in DEBIAN_RELEASES) 
            or "(unstable)" and "(not affected)" not in line]

    info_table = [ 
        line for line in info_table 
        if(
            "(security)" not in line and
            "vulnerable" in line and
            any(release in line for release in DEBIAN_RELEASES)
        )]

    debug("Filtered Info table and Fixed table")
    for line in info_table:
        debug(line)
    for line in fixed_table:
        debug(line)
    
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
                     advisory= None if line[5] == '' else line[5],
                     bugids= [] if not line[6]  else [(bug_id, False)],
                     vulnerable = [])
        convert_results.append(config)

    #If there's a line here, it means the release concerned by this line is vulnerable
    #see: filter_table
    for line in info_table:
        vc = vuln_config(version=line[2],
                         method="vulnerable"
                         )
        config2 = cve(package=line[0],
                     release=line[1],
                     vulnerable=[vc])
        convert_results.append(config2) 
   
    for config in convert_results:
        debug(f"{config.to_string()}\n")

    return convert_results


def versions_lookup(cve_list,browser,args):
    #might be smart to use flags to filter which method to use
    for cve in cve_list:
        cve.vulnerable_versions_lookup(browser, args)


       

if __name__ == "__main__":

    #TODO: CVE 2007-3910, no vulnerable version, not properly parsing table
    #TODO: CVE 2007-6355, not properly finding bug in DSA(finally, this seems fine)
    try: 
        browser = prepare_browser()
        args = argparse.Namespace()
        args.cve_number = "2007-3910"

        info_table, fixed_table = get_cve_tables_selenium(browser,args)
        info_table, fixed_table = filter_tables(info_table, fixed_table)
        cve_list = convert_tables(info_table, fixed_table)
        versions_lookup(cve_list,browser,args)

        debug("\nResults: \n")
        for cve in cve_list:
            debug(f"{cve.to_string()}\n")
        

    except FatalError as fatal_exc:
        print(fatal_exc, file = sys.stderr)
        sys.exit(1)

