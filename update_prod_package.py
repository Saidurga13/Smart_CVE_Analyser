import csv
import json

def get_product_pkg_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def get_agent2_updates_from_csv(csv_path):
    updates = {}
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            pkg = row["Package_Affected"]
            version = row["Fixed_Version"]
            updates[pkg] = version
    return updates

def update_pkg(pkg_json, updates):
    for pkg in pkg_json["pkg_list"]:
        name = pkg["pkg_name"]
        if name in updates:
            pkg["version"] = updates[name]
    return pkg_json

def save_updated_json(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)

def generate_updated_package_json(input_path, cve_csv_path, output_path):
    pkg_json = get_product_pkg_json(input_path)
    updates = get_agent2_updates_from_csv(cve_csv_path)
    updated_pkg_json = update_pkg(pkg_json, updates)
    save_updated_json(updated_pkg_json, output_path)
    return updated_pkg_json

def main():
    input_path = "product/packages.json"
    cve_csv_path = "cve_summary.csv"
    output_path = "update_packages.json"

    print("Updating package versions...")

    generate_updated_package_json(input_path, cve_csv_path, output_path)

    print(f"\nDone! Updated packages saved to: {output_path}")
    print("Build your product with this updated list for all CVE fixes.")

if __name__ == "__main__":
    main()
