# This Python script calculates the amount of coverage of the Australian and New Zealand IPv4 address space that 
# was achieved when using Censys to collect the research data
# Developed by Andrew Lin, 2023

# Import the necessary libraries/packages
import os
import ujson
from pathlib import Path
import multiprocessing
import ipaddress
import math

def process_file(json_file):
    """
    Function that processes a given JSON file, returning all found hosts/ip addresses
    """
    # Define an empty set to store the found addresses
    addresses = set()

    # Open and parse the JSON file
    with open(json_file, 'rb') as file:
        data = ujson.load(file)

        # Iterate through all hosts in the file, adding their addresses to the set
        for host in data:
            # Filters out Ipv6 addresses
            if (':' not in host["ip"]):
                addresses.add(host["ip"])
        return addresses

def check_address_in_subnets(addresses, subnets):
    """
    Function that checks the presence of addresses in the given subnets (using linear search)
    """
    # Define an empty set for subnets which have an address match
    matched_subnets = set()

    # Define a counter for the subnets list
    current_subnet_index = 0

    # Iterate through all addresses
    for address in addresses:
        # Find the subnet where the given address could potentially be
        while (current_subnet_index < len(subnets) - 1 and
               address > subnets[current_subnet_index].broadcast_address):
            current_subnet_index += 1

        # If the address is in the subnet, add the subnet to the appropriate set
        if address in subnets[current_subnet_index]:
            matched_subnets.add(subnets[current_subnet_index])
    return matched_subnets

def get_collected_addresses(country_code, addresses_file):
    """
    Function that gets and creates a file for the unique collected address for a given country (I.e NZ or AU)
    """
    # Define a path to where the data can be found
    data_path = Path("../Data/RawCensysData/")

    # Define a list to store the found JSON files
    json_files = []

    # Iterate through all folders and check if they match the specified country
    for current_folder in os.scandir(data_path):
        if (country_code in current_folder.name):
            # Recursively get all JSON files within the current specified folder 
            json_files += (list(Path(current_folder).rglob('*.json')))

    # Using multiprocessing, get all addresses into a (sorted) set
    with multiprocessing.Pool() as pool:
        addresses = pool.map(process_file, json_files)
    collected_addresses = set().union(*addresses)
    collected_addresses = sorted(collected_addresses)

    # Open a file to write the data to, then write all (non-excluded) addresses to the file
    dest_file = open(addresses_file, "w")
    for address in collected_addresses:
        if not any (ipaddress.IPv4Address(address) in net for net in excluded_networks_set):
            dest_file.write(address + "\n")
    dest_file.close()

def get_allocations(country_code, allocated_addresses_file, allocated_subnets_file):
    """
    Function that gets and creates files for the allocated addresses and subnets (assuming they do not exist) for a given country (I.e AU or NZ)
    """

    # Define empty sets for the allocated addresses and subnets
    allocated_addresses = set()
    allocated_subnets = set()

    # Define the path to where the allocation data can be found
    allocation_data = Path("../Data/allocation_data.txt")

    # Open the allocation data file for reading, iterating through all lines in the file
    allocation_file = open(allocation_data, 'r')
    for raw_line in allocation_file:
        # Splits the line based on the char | as a delimiter
        split_data = raw_line.split('|')

        # Check that we are processing the correct data
        if (len(split_data) == 7):
            # Defines variable for country code (E.g NZ) and data type (E.g asn)
            data_country = split_data[1]
            data_type = split_data[2]
            
            # Checks that the record is ipv4 and based in the correct country before processing
            if (data_country == country_code.upper() and data_type == "ipv4"):

                # Defines the starting and ending addresses of the range (based on the number of hosts in the range)
                start_address = ipaddress.IPv4Address(split_data[3])
                host_count = int(split_data[4])
                end_address = start_address + host_count

                # Checks whether the given file exists before proceeding
                if not(os.path.exists(allocated_addresses_file)):
                    # Iterate through all addresses in the range, adding them to the appropriate set if they are not excluded
                    for address in range(int(start_address), int(end_address)):
                        current_address = ipaddress.IPv4Address(address)

                        if not any (current_address in net for net in excluded_networks_set):
                            allocated_addresses.add(str(current_address))

                # Checks whether the given file exists before proceeding
                if not(os.path.exists(allocated_subnets_file)):
                    # Calculate the appropriate subnet mask for the given range
                    mask = int(-(math.log(host_count)/math.log(2) - 32))

                    # Add the address/mask combination to the appropriate set
                    allocated_subnets.add(ipaddress.ip_network(str(start_address) + "/" + str(mask), False))
    allocation_file.close()

    # Sort the two address and subnet sets
    allocated_addresses = sorted(allocated_addresses)
    allocated_subnets = sorted(allocated_subnets)
    
    # If the allocated addresses file for the given country does not exist, write all addresses to the new file
    if not(os.path.exists(allocated_addresses_file)):
        addresses_file = open(allocated_addresses_file, "w")
        for address in allocated_addresses:
            addresses_file.write(address + "\n")
        addresses_file.close()

    # If the allocated subnets file for the given country does not exist, write all subnets to the new file
    if not(os.path.exists(allocated_subnets_file)):
        subnets_file = open(allocated_subnets_file, "w")
        for subnet in allocated_subnets:
            subnets_file.write(str(subnet) + "\n")
        subnets_file.close()


def return_coverage(collected_addresses_file, allocated_addresses_file, allocated_subnets_file):
    """
    Function that returns the coverage (E.g how many allocated subnets have data) for a given country (I.e AU or NZ)
    """
    # Define empty sets for subnets and addresses that have matches
    matched_subnets = set()
    matched_addresses = set()

    # Get all allocated subnets for the given country from the appropriate file into a list
    with open(allocated_subnets_file, 'r') as subnets_file:
        subnets_data = [ipaddress.ip_network(subnet.strip()) for subnet in subnets_file]

    # Get all collected adddresses for the given country from the appropriate file into a list
    with open(collected_addresses_file, 'r') as collected_addresses:
        collected_addresses_data = [ipaddress.ip_address(address.strip()) for address in collected_addresses]

    with open(allocated_addresses_file, 'r') as allocated_addresses:
        allocated_addresses_data = [address.strip() for address in allocated_addresses]

    # Using the function check_address_in_subnets(), find all subnets with data/address matches
    matched_subnets = check_address_in_subnets(collected_addresses_data, subnets_data)

    # Using a set (for performance), find all (allocated) addresses that match with the collected data and add them to the appropriate set
    collected_addresses_set = set(collected_addresses_data)
    for allocated_address in allocated_addresses_data:
        if ipaddress.ip_address(allocated_address) in collected_addresses_set:
            matched_addresses.add(allocated_address)

    # Return the matching subnets and addresses
    return matched_subnets, matched_addresses

def print_summaries(matched_subnets, matched_addresses, total_subnets, total_addresses):
    """
    Function that display summary information about the scanning data (E.g the fraction of allocated subnets with data)
    """

    print("Number of allocated subnets with data: " + str(len(matched_subnets)))
    print("Total number of allocated subnets: " + str(total_subnets))
    print("Percentage of allocated subnets with data: " + str(round(len(matched_subnets) / total_subnets * 100, 1)) + "%")
    print()
    print("Number of allocated addresses with matches: " + str(len(matched_addresses)))
    print("Total number of allocated addresses: " + str(total_addresses))
    print("Percentage of allocated addresses with data: " + str(round(len(matched_addresses) / total_addresses * 100, 1)) + "%")


# Guard statement that checks if this script being run as module or main program
if __name__ == "__main__":
    # Define variables used to store the excluded networks
    excluded_networks_file = "Reference/ToReject.txt"
    excluded_networks_set = set()

    # Open the file containing the networks to exclude
    with open(excluded_networks_file, 'r') as file:
        # Extract the networks to be excluded by reading each line of the file
        for line in file:
            address = (line.split(' '))[0]
            excluded_network = ipaddress.ip_network(address)

            # Add the excluded network to the appropriate set
            excluded_networks_set.add(excluded_network)

    # Define variables for the filenames of the collected addresses data for NZ/AU
    collected_addresses_file_nz = "unique_collected_addresses_nz.txt"
    collected_addresses_file_au = "unique_collected_addresses_au.txt"

    # If the collected addresses file for either NZ and/or AU does not exist, use get_collected_addresses() to create the files
    if not(os.path.exists(collected_addresses_file_nz)):
        get_collected_addresses("nz", collected_addresses_file_nz)

    if not(os.path.exists(collected_addresses_file_au)):
        get_collected_addresses("au", collected_addresses_file_au)


    # Define variables for the filenames of the allocated addresses and subnets data for NZ/AU
    allocated_addresses_file_nz = "unique_allocated_addresses_nz.txt"
    allocated_subnets_file_nz = "unique_allocated_subnets_nz.txt"

    allocated_addresses_file_au = "unique_allocated_addresses_au.txt"
    allocated_subnets_file_au = "unique_allocated_subnets_au.txt"

    # If the allocated subnets and addresses files for either NZ and/or AU do not exist, use get_allocations() to create the files
    if not(os.path.exists(allocated_addresses_file_nz)) or not(os.path.exists(allocated_subnets_file_nz)):
        get_allocations("nz", allocated_addresses_file_nz, allocated_subnets_file_nz)
    
    if not(os.path.exists(allocated_addresses_file_au)) or not(os.path.exists(allocated_subnets_file_au)):
        get_allocations("au", allocated_addresses_file_au, allocated_subnets_file_au)


    ''' 
    Using return_coverage(), get all NZ and AU subnets with data, then display summary results such as the fraction of allocated subnets with data (for both countries),
    using print_summaries()
    '''
    matched_subnets_nz, matched_addresses_nz = return_coverage(collected_addresses_file_nz, allocated_addresses_file_nz, allocated_subnets_file_nz)
    matched_subnets_au, matched_addresses_au = return_coverage(collected_addresses_file_au, allocated_addresses_file_au, allocated_subnets_file_au)

    print("For New Zealand: ")
    total_subnets_nz = sum(1 for _ in open(allocated_subnets_file_nz))
    total_addresses_nz = sum(1 for _ in open(allocated_addresses_file_nz))
    print_summaries(matched_subnets_nz, matched_addresses_nz, total_subnets_nz, total_addresses_nz)
    print("---------------------------------------------------------------------------")
    print("For Australia: ")
    total_subnets_au = sum(1 for _ in open(allocated_subnets_file_au))
    total_addresses_au = sum(1 for _ in open(allocated_addresses_file_au))
    print_summaries(matched_subnets_au, matched_addresses_au, total_subnets_au, total_addresses_au)

