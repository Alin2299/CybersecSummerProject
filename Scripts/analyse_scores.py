# This Python script takes the scores files generated previously using get_scores.py, aggregates them into overall score files for AU and NZ, 
# and then analyses and graphs the data
# Developed by Andrew Lin, 2024

# Import the necessary libraries/packages
import os
from pathlib import Path
import os.path
import matplotlib.pyplot as plt
import numpy as np
import sys
from ipaddress import ip_network, ip_address
import re

# Guards the script from accidental execution 
if __name__ == "__main__":
    # Specify paths to the data/score files
    # au_data_path = "Data/Sample Data/AU"
    # nz_data_path = "Data/Sample Data/NZ"
    au_data_path = "Dataset-Latest/AU"
    nz_data_path = "Dataset-Latest/NZ"

    # Using the first command line argument, check if cloud providers should be factored into the program logic
    if (sys.argv[1] == "true" or sys.argv[1] == "True"):
        enable_cloud = True
    else:
        enable_cloud = False

    # Define string for checking if an endpoint is responsive or not
    no_response_string = "No result"

    # Define the path to the file that will contain all AU score data
    overall_au_file = Path(au_data_path + "/" + "overall_au_scores.txt")

    # Checks that the file doesn't exist before proceeding; if it does, print a message
    if not os.path.exists(overall_au_file):
        # Get all individual score files for AU
        au_score_files = list(Path(au_data_path).rglob("*scores.txt"))

        # Write all data for each individual file into the overall scores file whilst filtering out non-responsive endpoints
        with open(overall_au_file, "a") as overall_score_file:
            for score_file in au_score_files:
                with open(score_file, "r") as score_file:
                    for line in score_file:
                        if no_response_string not in line:
                            overall_score_file.write(line.strip() + "\n")
    else:
        print(str(overall_au_file) + " already exists")

    # Define the path to the file that will contain all NZ score data
    overall_nz_file = Path(nz_data_path + "/" + "overall_nz_scores.txt")

    # Checks that the file doesn't exist before proceeding; if it does, print a message
    if not os.path.exists(overall_nz_file):
        # Get all individual score files for NZ
        nz_score_files = [file for file in Path(nz_data_path).rglob("*") if 'scores' in file.name and file.suffix == '.txt']

        # Write all data for each individual file into the overall scores file whilst filtering out non-responsive endpoints
        with open(overall_nz_file, "a") as overall_score_file:
            for score_file in nz_score_files:
                with open(score_file, "r") as score_file:
                    for line in score_file:
                        if no_response_string not in line:
                            overall_score_file.write(line.strip() + "\n")
    else:
        print(str(overall_nz_file) + " already exists")


    def calc_tls_data(file_path):
        """
        Function that takes a score file and returns data about the SSL/TLS version prevalence

        file_path: The path to the score file
        """

        # Define counter for total number of targets/endpoints and dictionary for version counting
        total_targets = 0
        versions_count = {
            "TLSv1.3": 0,
            "TLSv1.2": 0,
            "TLSv1.1": 0,
            "TLSv1.0": 0,
            "SSLv3": 0,
            "SSLv2": 0
        }

        # Open the score file and read each line, incrementing the total target and versions counter (where applicable)
        with open(file_path, "r") as file:
            for line in file:
                total_targets += 1
                for version in versions_count:
                    if version in line:
                        versions_count[version] += 1

        # Return the prevalence (as % of total targets) for each version, count pair
        return {version: count / total_targets * 100 for version, count in versions_count.items()}
    

    def graph_tls_version_data():
        """
        Function that plots the SSL/TLS version prevalence data (as a grouped bar chart)
        """
        # Define lists for graphing based on the appropriate dictionaries
        au_names = list(au_results.keys())
        au_values = list(au_results.values())

        nz_names = list(nz_results.keys())
        nz_values = list(nz_results.values())

        # Set the (relative) positioning of the groups
        n_groups = len(au_results)
        index = np.arange(n_groups)
        bar_width = 0.35

        # Plot the data as a bar graph
        fig, ax = plt.subplots()
        au_bars = ax.bar(index, au_values, bar_width, label='Australia')
        nz_bars = ax.bar(index + bar_width, nz_values, bar_width, label='New Zealand')

        # Give the plot labels/other details
        ax.set_xlabel('SSL/TLS version')
        ax.set_ylabel('Percentage')
        ax.set_title('SSL/TLS Version Prevalence by Country')
        ax.set_xticks(index + bar_width / 2)
        ax.set_xticklabels(au_names)
        ax.legend()

        # Save the plot as a png
        plt.savefig("tls_version_prevalance_by_country.png", dpi=300)


    def calc_endpoint_data():
        """
        Function that calculates the change in endpoint reponsiveness over the total scanning period and changes in endpoint count
        and then graphs the data
        """

        def check_cloud(ip_str):
            """
            Internal function that checks a given IP address against the cloud provider prefix ranges
            """
            ip_num = int(ip_address(ip_str))
            return any(start <= ip_num <= end for start, end in cloud_prefix_ranges)
        
        # Define a dictionary to store the date and associated endpoints (in a list) for Australia
        au_endpoint_counter = {}
        
        # If the user has requested (specifically) cloud provider data, preprocess the cloud provider ranges to check against
        if enable_cloud == True:
            cloud_prefix_ranges = []
            with open("overall-consolidated.txt", "r") as file:
                for line in file:
                    network = ip_network(line.strip(), strict=False)
                    start = int(network.network_address)
                    end = int(network.broadcast_address)
                    cloud_prefix_ranges.append((start, end))

        # Iterate through each file in the AU data path
        for file in os.scandir(au_data_path):
            # Checks that the file is an actual scores file before proceeding
            if file.is_dir() or "overall" in file.name:
                continue
            
            # Define the list to store all endpoints (for a date)
            list_endpoints = []
                
            # Set the appropriate scores file
            scores_file = file

            # Iterate through each line in the scores file and extract the endpoint on each line, adding it to the list
            with open(scores_file, "r") as file:
                for line in file:
                    # Skip lines with non-responsive endpoints
                    if no_response_string in line:
                        continue

                    # Only allow cloud provider related lines/data if specified by the user             
                    if enable_cloud == True:
                        # Skips lines with non cloud-provider endpoints
                        if (check_cloud(line.split(",")[0].strip()) == False):
                            continue

                    # Extract the data from the line and add it to the appropriate list
                    comma_split_data = line.split(",")
                    endpoint_string = comma_split_data[0] + "," + comma_split_data[1]
                    list_endpoints.append(endpoint_string)

            # Add the date and endpoints list pair to the appropriate dictionary
            au_endpoint_counter[scores_file.name.replace("-scores.txt", "")] = list_endpoints


        # Define a dictionary to store the date and associated endpoints (in a list) for New Zealand
        nz_endpoint_counter = {}

        # Iterate through each file in the NZ data path
        for file in os.scandir(nz_data_path):
            # Checks that the file is actually a proper scores file (such as results-nz-20230519-scores.txt) before proceeding
            if not "results" in file.name or not "scores.txt" in file.name:
                continue

            # Define the list to store all the endpoints (for a date)
            list_endpoints = []

            # Iterate through each line in the scores file and extract the endpoint on each line, adding it to the list
            with open(file, "r") as scores_file:
                for line in scores_file:
                    # Skip lines with non-responsive endpoints
                    if no_response_string in line:
                        continue
                    
                    # Extract the data from the line and add it to the appropriate list
                    comma_split_data = line.split(",")
                    endpoint_string = comma_split_data[0] + "," + comma_split_data[1]
                    list_endpoints.append(endpoint_string)
            
            # Add the date and endpoints list pair to the appropriate dictionary
            nz_endpoint_counter[file.name.replace("results-", "").split("-scores.txt")[0]] = list_endpoints

        # Sort the two dictionaries by date (Earliest to latest)
        sorted_nz_count = dict(sorted(nz_endpoint_counter.items(), key=lambda item: item[0].split('-')[1]))
        sorted_au_count = dict(sorted(au_endpoint_counter.items(), key=lambda item: item[0].split('-')[1]))

        # Define lists for graphing
        au_names = list(sorted_au_count.keys())
        au_values = [len(list) for list in sorted_au_count.values()]
        au_values = [(count - au_values[0]) / au_values[0] * 100 for count in au_values]

        nz_names = list(sorted_nz_count.keys())
        nz_values = [len(list) for list in sorted_nz_count.values()]

        # Modify the strings in the name lists for conciseness
        au_names = [name.replace("au-2023", "") for name in au_names]
        nz_names = [name.replace("nz-2023", "") for name in nz_names]

        # Define the width of the bars
        bar_width = 0.35

        # Define the x-coords for the plot based on the number of elements in au_names, and set a new figure
        index_au = np.arange(len(au_names))
        plt.figure(figsize=(10, 5))

        # Create the bar graph plot for Australia
        plt.bar(index_au, au_values, bar_width, label='Australia')

        # Change the AU plots details depending on whether cloud provider data is to be shown or not
        if enable_cloud == True:
            au_title = "Cloud Provider "
            au_plot_name = "au_cloud"
        else:
            au_title = ""
            au_plot_name = "au"

        # Add details/labels to the plot
        plt.xlabel('Date (MMDD)')
        plt.ylabel('Percent change in endpoints')
        plt.title("Percent change of " + au_title + "Endpoints over time in Australia")
        plt.grid(axis='y')
        plt.xticks(index_au, au_names)

        # Ensure that the plot elements fit properly
        plt.tight_layout()

        # Save the plot as a png
        plt.savefig(au_plot_name + "_endpoint_responsiveness.png", dpi=300)


        # Define the x-coords for the plot based on the number of elements in nz_names, and set a new figure
        index_nz = np.arange(len(nz_names))
        plt.figure(figsize=(10, 5))

        # Create the bar graph plot for New Zealand
        plt.bar(index_nz, nz_values, bar_width, color='orange', label='New Zealand')

        # Add details/labels to the plot
        plt.xlabel('Date (MMDD)')
        plt.ylabel('Number of endpoints')
        plt.title('Endpoints over time in New Zealand')
        plt.xticks(index_nz, nz_names)
        plt.grid(axis='y')

        # Ensure that the plot elements fit properly
        plt.tight_layout() 

        # Save the plot as a png
        plt.savefig("nz_endpoint_responsiveness.png", dpi=300)


        # Set the lists at the corresponding date midpoint to be used as reference
        reference_list_au = list(sorted_au_count.values())[len(au_values) // 2]
        reference_list_nz = list(sorted_nz_count.values())[len(nz_values) // 2]

        # Calculate the endpoint change for Australia as a percentage change
        au_endpoint_change = [(len(set(reference_list_au) & set(list))) / len(reference_list_au) * 100 for list in sorted_au_count.values()]

        # Calculate the endpoint change for New Zealand as a percentage change
        nz_endpoint_change = [(len(set(reference_list_nz) & set(list))) / len(reference_list_nz) * 100 for list in sorted_nz_count.values()]

        # Set up the figure for plotting for Australia
        plt.figure(figsize=(13, 7))

        # Plot the stacked area plot for Australia
        plt.stackplot(au_names, au_endpoint_change, labels=['Australia'])

        # Add a reference line at the dates midpoint
        plt.axvline(x=len(au_values) // 2, color='grey', linestyle='--')

        # Add other plot details such as labels and title
        plt.xlabel('Date (MMDD)', fontsize=16)
        plt.ylabel('Percent of Same Endpoints', fontsize=16)
        plt.title("Relative " + au_title + "Endpoints Difference over Time for Australia", fontsize=17)
        plt.xticks(fontsize=16)
        plt.yticks(fontsize=16)
        plt.tight_layout()

        # Save the plot as a png
        plt.savefig(au_plot_name + "_relative_endpoint.png", dpi=300)


        # Set up the figure for plotting for New Zealand
        plt.figure(figsize=(13, 7))

        # Plot the stacked area plot for New Zealand
        plt.stackplot(nz_names, nz_endpoint_change, labels=['New Zealand'], colors=["orange"])

        # Add other plot details such as labels and title
        plt.xlabel('Date (MMDD)', fontsize=16)
        plt.ylabel('Percent of Same Endpoints', fontsize=16)
        plt.title('Relative Endpoints Difference over Time for New Zealand', fontsize=17)
        plt.xticks(fontsize=16)
        plt.yticks(fontsize=16)
        plt.tight_layout()

        # Add a reference line at the dates midpoint
        plt.axvline(x=len(nz_values) // 2, color='grey', linestyle='--')

        # Save the plot as a png
        plt.savefig("nz_relative_endpoint.png", dpi=300)


    def graph_bubble_chart():
        """
        Function that calculates and graphs bubble charts for comparing security factors between AU and NZ
        """
        # Define a dict that stores key:value pairs of (SSL/TLS version, score): number of endpoints that support that combination
        tls_score_dict = {}

        # Define a list to store all possible SSL/TLS version and score combinations
        version_score_key_list = []

        def process_data(overall_scores):
            """
            Internal function that processes an overall scores file and returns the relevant data 
            (supported versions, scores, and number of endpoints for a given version score combination) as 3 lists

            overall_scores: The file to be processed
            """
            with open(overall_scores, "r") as scores_file:
                # Iterate through each line in the scores file
                for line in scores_file:
                    # Skip lines with non-responsive endpoints
                    if no_response_string in line:
                        continue
                    # Using a regex pattern, find all SSL/TLS versions supported (by the endpoint)
                    version_pattern = "\\bTLSv1.[0-3]|\\bSSLv[2-3]"
                    supported_versions = re.findall(version_pattern, line)

                    # Split the line of data (using a comma) to get the score associated with the endpoint
                    comma_split_data = line.split(",")
                    score = comma_split_data[2]

                    # Iterate through all SSL/TLS versions in the respective list
                    for version in supported_versions:
                        # Add the version, score combination to the appropriate list if it doesn't already exist
                        if not (version + "," + score) in version_score_key_list:
                            version_score_key_list.append(version + "," + score)

                        # Iterate through all version, score combinations
                        for version_score in version_score_key_list:
                            # Initialise the version, score combination with an endpoint count of 0 if it doesn't exist
                            if not version_score in tls_score_dict:
                                tls_score_dict[version_score] = 0
                            # If the endpoint supports/has the specific SSL/TLs version and score (combination), increment the associated counter
                            if version in version_score.split(",") and score in version_score.split(","):
                                tls_score_dict[version_score] += 1

            # Define the 3 lists to return, as well as the order that the versions should be displayed (on the graphs)
            versions, scores, sizes = [], [], []
            version_order = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
            
            # Sort the dictionary data by the version order and return a list of tuples
            sorted_dict_data = sorted(tls_score_dict.items(), key=lambda x: version_order.index(x[0].split(",")[0]))

            # Iterate through each item in the list of tuples and extract/append the data, then return the 3 lists
            for key, count in sorted_dict_data:
                version, score = key.split(",")
                versions.append(version)
                scores.append(int(score))
                sizes.append(count)
            # sizes = [size / 1000 for size in sizes] 
            return versions, scores, sizes
        
        # Get the data for both Australia and NZ using the internal function process_data()
        au_versions, au_scores, au_sizes = process_data(overall_au_file)
        nz_versions, nz_scores, nz_sizes = process_data(overall_nz_file)

        # Define a new figure for the plot, then plot the bubble chart for Australia (with the sizes/endpoint counts being scaled)
        plt.figure(figsize=(10, 6))
        plt.scatter(au_versions, au_scores, s=au_sizes, color="blue", alpha=0.5)

        # Add other details such as labels to the plot, and ensure plot elements are appropriately formatted/sized
        plt.xlabel('TLS/SSL Version')
        plt.ylabel('Score (Lower is better)')
        plt.title('Bubble Chart of TLS/SSL Versions, Scores, and Endpoint Counts for Australia')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Save the plot as a png
        plt.savefig("au_version_score_bubble_chart.png", dpi=300)

        # Define a new figure for the plot, then plot the bubble chart for New Zealand (with sizes/endpoint counts being scaled)
        plt.figure(figsize=(10, 6))
        plt.scatter(nz_versions, nz_scores, s=nz_sizes, color="green", alpha=0.5)

        # Add other details such as labels to the plot, and ensure plot elements are appropriately formatted/sized
        plt.xlabel('TLS/SSL Version')
        plt.ylabel('Score (Lower is better)')
        plt.title('Bubble Chart of TLS/SSL Versions, Scores, and Endpoint Counts for New Zealand')
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Save the plot as a png
        plt.savefig("nz_version_score_bubble_chart.png", dpi=300)



    def calc_long_data():
        """
        Function that calculates and graphs longitudinal data
        """

        def get_data(data_path):
            """
            Internal function that gets the raw AU and NZ data for plotting into dictionaries

            data_path: Path to where the appropriate data is located

            Returns: 
            endpoints_dict: Dictionary for AU/NZ that contains date and {version, endpoint} pairs
            totals_dict: Dictionary for AU/NZ that contains date and total endpoint count pairs
            """
            # Define dictionaries for tracking version, endpoint data, and total endpoint count data
            endpoints_dict = {}
            totals_dict = {}
            
            # Iterate through each file in the given data path
            for file in os.scandir(data_path):
                # Checks that the file is an actual scores file before proceeding
                if file.is_dir() or "overall" in file.name or ".tgz" in file.name:
                    continue
                
                # Define a dictionary to store all endpoints (for a date)
                version_count_dict = {}

                # Define variable to track the total endpoints count for the given scores file
                total_endpoints = 0
                    
                # Set the appropriate scores file
                scores_file = file

                # Iterate through each line in the scores file and extract the version support data on each line
                with open(scores_file, "r") as file:
                    for line in file:
                        # Skip lines with non-responsive endpoints
                        if no_response_string in line:
                            continue

                        total_endpoints += 1

                        # Using a regex pattern, find all SSL/TLS versions supported (by the endpoint)
                        version_pattern = "\\bTLSv1.[0-3]|\\bSSLv[2-3]"
                        supported_versions = re.findall(version_pattern, line)

                        # Iterate through all the supported versions, and initialise and increment the counters where appropriate
                        for version in supported_versions:
                            if version not in version_count_dict.keys():
                                version_count_dict[version] = 0
                            version_count_dict[version] += 1

                # Sort the dictionary based on the previously defined version order
                version_count_dict = dict(sorted(version_count_dict.items(),  key=lambda x: version_order.index(x[0].split(",")[0])))

                # Add the date and endpoints dict pair to the appropriate dictionary
                endpoints_dict[scores_file.name.replace("-scores.txt", "")] = version_count_dict

                # Add the date and total endpoints count pair to the appropriate dictionary
                totals_dict[scores_file.name.replace("-scores.txt", "")] = total_endpoints

            # Return the appropriate data
            return endpoints_dict, totals_dict
            

        def process_data(sorted_count, totals_dict):
            """
            Internal function that processes the dictionary data (for both AU and NZ) for plotting

            sorted_count: Dictionary that contains date and {version, count} pairs (Sorted by earliest to latest date)
            totals_dict: Dictionary that contains date and total endpoint count (for each date/week) pairs
            """
            # Initialise a dictionary to store counts for each TLS version over time
            version_counts_over_time = {version: [] for version in tls_versions}

            # Extract/calculate counts for each version across all dates
            for date, version_dict in sorted_count.items():
                for version in tls_versions:
                    count = version_dict.get(version, 0)  # Use 0 if the version is not present on that date
                    version_counts_over_time[version].append(count)

            for version in tls_versions:
                baseline = version_counts_over_time[version][0] if version_counts_over_time[version] else 1
                version_counts_over_time[version] = [(count - baseline) / baseline * 100 for count in version_counts_over_time[version]]

            # for date, version_dict in sorted_count.items():
            #     total_endpoints = totals_dict[date]  # Assuming you've stored this count
            #     for version in tls_versions:
            #         count = version_dict.get(version, 0)
            #         normalized_count = count / total_endpoints if total_endpoints else 0
            #         version_counts_over_time[version].append(normalized_count)

            # for version in tls_versions:
            #     baseline = version_counts_over_time[version][0] if version_counts_over_time[version] else 0
            #     version_counts_over_time[version] = [(value - baseline) / baseline * 100 if baseline != 0 else 0 for value in version_counts_over_time[version]]

            return version_counts_over_time


        # Define the order that the versions should be displayed (on the graphs)
        version_order = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

        # Define and initialise dictionaries (for both AU and NZ) to store date and associated version, count and total count pairs
        au_endpoint_counter, au_total_endpoints_per_week = get_data(au_data_path)
        nz_endpoint_counter, nz_total_endpoints_per_week = get_data(nz_data_path)

        # Sort the two dictionaries by date (Earliest to latest)
        sorted_nz_count = dict(sorted(nz_endpoint_counter.items(), key=lambda item: item[0].split('-')[1]))
        sorted_au_count = dict(sorted(au_endpoint_counter.items(), key=lambda item: item[0].split('-')[1]))

        # Define lists for graphing
        au_names = list(sorted_au_count.keys())
        au_values = [(list) for list in sorted_au_count.values()]

        nz_names = list(sorted_nz_count.keys())
        nz_values = [(list) for list in sorted_nz_count.values()]

        # Modify the strings in the name lists for conciseness
        au_names = [name.replace("au-2023", "") for name in au_names]
        nz_names = [name.replace("nz-2023", "") for name in nz_names]

        # Determine all the TLS versions present in the data
        tls_versions = set()
        for date_dict in sorted_au_count.values():
            tls_versions.update(date_dict.keys())

        tls_versions = sorted(tls_versions, key=lambda x: version_order.index(x))

        au_version_counts_over_time = process_data(sorted_au_count, au_total_endpoints_per_week)
        nz_version_counts_over_time = process_data(sorted_nz_count, nz_total_endpoints_per_week)

        # Plot the data for Australia
        plt.figure(figsize=(14, 8))
        for version, counts in au_version_counts_over_time.items():
            dates = [key.replace("au-2023", "") for key in sorted_au_count.keys()]
            plt.plot(dates, counts, label=version)

        # Add other plot details such as labels and a title
        plt.xlabel("Date (MMDD)", fontsize=15)
        plt.ylabel("Percent Change in Endpoint Count", fontsize=15)
        plt.title("Percent Change in SSL/TLS Version Support Over Time in Australia", fontsize=16)
        plt.legend()
        plt.xticks(rotation=45)
        plt.grid(axis='y')

        plt.tick_params(axis='x', labelsize=15)
        plt.tick_params(axis='y', labelsize=15)

        # Ensure plot elements fit appropriately
        plt.tight_layout()

        # Save the plot as a png
        plt.savefig("tls_support_long_au.png", dpi=300)

        # Plot the data for New Zealand
        plt.figure(figsize=(14, 8))
        for version, counts in nz_version_counts_over_time.items():
            dates = [key.replace("results-nz-2023", "") for key in sorted_nz_count.keys()]
            plt.plot(dates, counts, label=version)

        # Add other plot details such as labels and a title
        plt.xlabel("Date (MMDD)", fontsize=15)
        plt.ylabel("Percent Change in Endpoint Count", fontsize=15)
        plt.title("Percent Change in SSL/TLS Version Support Over Time in New Zealand", fontsize=16)
        plt.legend()
        plt.xticks(rotation=45)
        plt.grid(axis='y')

        plt.tick_params(axis='x', labelsize=15)
        plt.tick_params(axis='y', labelsize=15)

        # Ensure plot elements fit appropriately
        plt.tight_layout()

        # Save the plot as a png
        plt.savefig("tls_support_long_nz.png", dpi=300)


    # Prints the AU and NZ prevalence data
    print("Australia prevalence:")
    au_results = calc_tls_data(overall_au_file)
    for version, percentage in au_results.items():
        print(f"{version}: {percentage:.2f}%")

    print()

    print("NZ prevalence:")
    nz_results = calc_tls_data(overall_nz_file)
    for version, percentage in nz_results.items():
        print(f"{version}: {percentage:.2f}%")
    
    # # Use a function to graph the SSL/TLS prevalence data
    graph_tls_version_data()

    # Use a function to calculate and graph data related to endpoint responsiveness and change over time
    calc_endpoint_data()

    # Use a function to graph bubblecharts
    graph_bubble_chart()

    # # Use a function to calculate and graph longitudinal (20-weeks) (endpoint) data
    calc_long_data()