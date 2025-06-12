import pytest
from decret.proto import * 
from collections import Counter
import re

# ===================== Global Fixtures ===================== 

@pytest.fixture(scope="session")
def cve_numbers():
    file_path = "tests/cves_head.txt"
    try: 
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        pytest.fail(f"Error reading CVE file: {str(e)}")


@pytest.fixture(scope="session")
def browser():
    return prepare_browser()


# ===================== TESTING Finding and cleaning Tables ===================== 

validation_rules_fixed = [
    lambda val: val != "",                                # Package: non-empty
    lambda val: val != "",                                # Source: non-empty
    lambda val: any(val.startswith(rel) for rel in DEBIAN_RELEASES),  # Release
    lambda val: val in ["(unfixed)", "(not-affected)"] or val != "",  # Fixed
    lambda val: val in ["unimportant", "low", "medium", "high", ""],  # Urgency
    lambda val: val == "" or val.startswith("DSA") or val.startswith("DLA"),  # Origin
    lambda val: val == "" or re.fullmatch(r"\d+", val) is not None   # Bug
]

info_fields = {
    'Package': [],#Non empty
    'Release' : DEBIAN_RELEASES,
    'Fixed' : ["(unfixed)","(not-affected)"], #Or non-empty
    'Status' : ["fixed","vulnerable"],#Or non-empty
}

@pytest.fixture(scope="session")
def found_tables(cve_numbers, browser):
    results = {}
    errored_on_search = []

    for cve_number in cve_numbers:
        args = argparse.Namespace()
        args.cve_number = cve_number

        try:
            info_table, fixed_table = get_cve_tables_selenium(browser,args)
            results[cve_number] = (info_table,fixed_table)
        except Exception as e:
            errored_on_search.append((cve_number,e))
            continue

    return results


@pytest.fixture(scope="session")
def filtered_tables(found_tables):
    results = {}
    for cve,(info_table,fixed_table) in found_tables.items():
        info_table, fixed_table = filter_tables(info_table, fixed_table)
        results[cve] = (info_table, fixed_table)
    return results
 
def test_searching_tables(found_tables):
    #These tests might seem strict, but the idea is 
    #to ensure we get the most information possible
    #so it is easier to re-use information for new strategies
    #so no filtering should be applied at this stage
    
    for cve_number, (info_list,fixed_list) in found_tables:
        #Also assert size
        for i, val in enumerate(fixed_list):
            assert validation_rules_fixed[i](val), f"Invalid value for '{val}' in position {i}"


    """
    assert "2020-7247" in found_tables
    info_table, fixed_table = found_tables["2020-7247"]
    assert len(info_table) == 4 and len(fixed_table) == 3
    #Checking fixed_table
    expected = ["opensmtpd", "stretch", "6.0.2p1-2+deb9u2", "DSA-4611-1"]
    assert all(elem in fixed_table[0] for elem in expected)
    expected = ["opensmtpd", "buster", "6.0.3p1-5+deb10u3", "DSA-4611-1"]
    assert all(elem in fixed_table[1] for elem in expected)
    expected = ["opensmtpd", "(unstable)", "6.6.2p1-1", "950121"]
    assert all(elem in fixed_table[2] for elem in expected)

    assert "2014-0160" in found_tables
    info_table, fixed_table = found_tables["2014-0160"]
    assert len(info_table) == 5 and len(fixed_table) == 3
    #Checking Entries
    expected = ["openssl", "squeeze", "(not affected)"]
    assert all(elem in fixed_table[0] for elem in expected)
    expected = ["openssl", "wheezy", "1.0.1e-2+deb7u5", "DSA-2896-1"]
    assert all(elem in fixed_table[1] for elem in expected)
    expected = ["openssl", "(unstable)", "1.0.1g-1", "743883"]
    assert all(elem in fixed_table[2] for elem in expected)


    assert "2021-3156" in found_tables
    info_table, fixed_table = found_tables["2021-3156"]
    assert len(info_table) == 3 and len(fixed_table) == 3

    for info_table, fixed_table in found_tables.values():
        for line_fixed in fixed_table:
            assert len(line_fixed) == 7 , f"line: {line_fixed} is not of correct format"

            assert (any(line_fixed[2].startswith(release) for release in DEBIAN_RELEASES)
                   or line_fixed[2] == "(unstable)")

        for line_info in info_table:
            assert len(line_info) >= 4 , f"line: {line_info} is not of correct format"
            assert all(line_info), "some table elements are empty"

            assert (any(line_info[1].startswith(release) for release in DEBIAN_RELEASES)
                   or line_info[1] == "(unstable)")
"""


# ===================== TESTING Conversion to cve object list ===================== 
@pytest.fixture(scope="session")
def converted_tables(filtered_tables):
    results = {}
    for cve,(info_table,fixed_table) in filtered_tables.items():
        cve_list = convert_tables(info_table, fixed_table)
        results[cve] = cve_list
    return results


@pytest.fixture(scope="session")
def vuln_configs(browser,converted_tables):
    errored_on_search = []
    failed_to_find = []
    counter = { "Vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 
    n_cves = 0
    results = {}

    for cve_number, cve_list in converted_tables.items():
        n_cves += 1

        args = argparse.Namespace()
        args.cve_number = cve_number

        versions_lookup(cve_list,browser,args)

        for cve in cve_list:
            for config in cve.vulnerable:
                counter[config.method] += 1 
            if sum(counter.values()) == 0:
                failed_to_find.append(cve)
         
        results[cve_number]=((counter.copy(),cve_list))
        counter = { "Vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 

    #TODO: Maybe move this to a test 
    print(f"Out of {n_cves}, {len(errored_on_search)} errored on search \n" 
          f"and decret failed to find vuln configs for: {len(failed_to_find)}")

    print("ERRORS:\n")
    print("Errored on search")
    for cve,error in errored_on_search:
        print(f"{cve} failed with: \n {error}")
    
    print("Failed to find")
    for cve in failed_to_find:
        print(cve)
  
    total = { "vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 
    print("RESULTS:\n")
    for number , (counter,cves) in results.items():
        print(f"{number} \n {counter} \n")
        total = Counter(total) + Counter(counter)
        for cve in cves:
            print(cve.to_string())

    print(f" Vulnerable configurations where found the following way: \n{total}"
          f"\n for a total of {sum(total.values())} vulnerable configs")

    return results



def test_vuln_configs(vuln_configs):
    print(vuln_configs)
