from decret.proto import *
from collections import Counter

def testing(file_path, browser):
    try:
        with open(file_path, 'r') as file:
            cve_numbers = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return

    results = {}
    errored_on_search = []
    failed_to_find = []
    counter = { "vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 
    n_cves = 0

    for cve_number in cve_numbers:
        n_cves += 1

        args = argparse.Namespace()
        args.cve_number = cve_number

        try:
            info_table, fixed_table = get_cve_tables_selenium(browser,args)
        except Exception as e:
            errored_on_search.append((cve_number,e))
            continue

        info_table, fixed_table = filter_tables(info_table, fixed_table)
        cve_list = convert_tables(info_table, fixed_table)
        versions_lookup(cve_list,browser,args)

        for cve in cve_list:
            for config in cve.vulnerable:
                counter[config.method] += 1 
            if sum(counter.values()) == 0:
                failed_to_find.append(cve_number)
     
         
        results[cve_number]=((counter.copy(),cve_list))
        counter = { "vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 

    print(f"Out of {n_cves}, {len(errored_on_search)} errored on search \n" 
          f"and decret failed to find vuln configs for: {failed_to_find}")

    print("ERRORS:\n")
    print("Errored on search")
    for cve,error in errored_on_search:
        print(f"{cve} failed with: \n {error}")
    
    print("Failed to find")
    for cve in failed_to_find:
        print(cve)
  
    total = { "vulnerable": 0, "DSA": 0, "N-1": 0, "Bug":0 } 
    print("RESULTS:\n")
    for number,counter,cves in results:
        print(f"{number} \n {counter} \n")
        total = Counter(total) + Counter(counter)
        for cve in cves:
            print(cve.to_string())

    print(f" Vulnerable configurations where found the following way: \n{total}"
          f"\n for a total of {sum(total.values())} vulnerable configs")

#TODO test this and the errors in:  python -m pytest tests/test_proto.py

