# This Python script analyses CSV files (for both Australia and New Zealand) that contains a list of endpoints
# and their associated data (such as SSL/TLS version and ciphersuite support) and creates plots/visualisations of the data
# Developed by Andrew Lin, 2024

# Import the necessary packages/libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import seaborn as sns


# Define the path to the CSV files for the latest AU and NZ snapshots
overall_au_snapshot = Path("Data/Sample Data/Other Data/au-20230922/au-20230922.csv")
overall_nz_snapshot = Path("Data/Sample Data/Other Data/nz-20230922/nz-20230922.csv")

# Import both CSV files as dataframes (using Pandas)
au_df = pd.read_csv(overall_au_snapshot)
nz_df = pd.read_csv(overall_nz_snapshot)

# Define a list for the proper order for the SSL/TLS versions to be displayed in, then use it to get the correlation data
ordered_versions = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
au_corr = au_df[ordered_versions].corr()
nz_corr = nz_df[ordered_versions].corr()

# Generate a mask for the upper triangle
au_mask = np.triu(np.ones_like(au_corr, dtype=bool))
nz_mask = np.triu(np.ones_like(nz_corr, dtype=bool))

# Set up the matplotlib figure
fig, axes = plt.subplots(1, 2, figsize=(16, 7))

# Customize the font properties for the annotations
font_options = {'fontsize': 15, 'fontweight': 'bold', 'color': 'white'}

# Draw the heatmap with the mask for Australia using seaborn
sns.heatmap(au_corr, mask=au_mask, cmap='coolwarm', annot=True, annot_kws=font_options, cbar=False, ax=axes[0])
axes[0].set_title('SSL/TLS version Correlation Matrix for Australia', fontsize=17)

# Draw the heatmap with the mask for New Zealand using seaborn
sns.heatmap(nz_corr, mask=nz_mask, cmap='coolwarm', annot=True, annot_kws=font_options, cbar=False, ax=axes[1])
axes[1].set_title('SSL/TLS version Correlation Matrix for New Zealand', fontsize=17)

# Customize the tick labels for both axes
for ax in axes:
    ax.tick_params(axis='x', labelsize=15, labelrotation=45)
    ax.tick_params(axis='y', labelsize=15)

# Adjust the layout
plt.tight_layout()

# Save the plots as a png file
plt.savefig("tls_version_correlation.png", dpi=400)


# Define the IANA standard port for HTTPS as a constant
STANDARD_PORT = 443

# Create separate dataframes for AU and NZ, categorised by port type (Standard vs non-standard)
au_std_port_df = au_df[au_df["PORT"] == STANDARD_PORT]
au_non_std_port_df = au_df[au_df["PORT"] != STANDARD_PORT]

nz_std_port_df = nz_df[nz_df["PORT"] == STANDARD_PORT]
nz_non_std_port_df = nz_df[nz_df["PORT"] != STANDARD_PORT]


def count_factors(df):
    """
    Internal function that processes a dataframe and counts factor support

    df: The dataframe to be processed

    Returns: A dictionary with factor: count pairs
    """

    # Define a list for the other factors/vulnerabilities to consider
    other_factors = ["AES", "3DES", "MD5", "EXPORT"]

    # Count the support for the different SSL/TLS versions
    port_count_dict = {version: df[version].sum() for version in ordered_versions}

# Iterate through each factor in the list of other factors to consider
    for factor in other_factors:
        # Define a boolean array corresponding to the relevant columns
        factor_columns = df.columns.str.contains(factor)

        # Filter the dataframe to only include columns related to the current factor
        factor_support = (df.loc[:, factor_columns] == 1).any(axis=1)

        # Count how many times each factor is supported for all relevant rows
        port_count_dict[factor] = factor_support.sum()

    # Return the dictionary
    return port_count_dict
    
# Define variables for Australia to be used for plotting
au_num_std_endpoints = len(au_std_port_df)
au_num_non_std_endpoints = len(au_non_std_port_df)

au_std_port_count = count_factors(au_std_port_df)
au_non_std_port_count = count_factors(au_non_std_port_df)

au_std_factors = list(au_std_port_count.keys())
au_std_counts = list(au_std_port_count.values())

au_non_std_factors = list(au_non_std_port_count.keys())
au_non_std_counts = list(au_non_std_port_count.values())

# Update the counts lists to be relative (as a percentage) to the corresponding (std vs non-std) endpoint totals
au_std_counts = [(count / au_num_std_endpoints) * 100 for count in au_std_counts]
au_non_std_counts = [(count / au_num_non_std_endpoints) * 100 for count in au_non_std_counts]

# Setup for plotting 
n_groups = len(au_std_counts)
index = np.arange(n_groups)
bar_width = 0.35
plt.figure(figsize=(17, 6))

# Plot the data comparing std vs non-std ports as a grouped bar graph
fig, ax = plt.subplots()
au_std_bars = ax.bar(index, au_std_counts, bar_width, label='Standard Port')
au_non_std_bars = ax.bar(index + bar_width, au_non_std_counts, bar_width, label='Non-standard Port')

# Add other details to the graph such as labels, and ensure the formatting/sizing is appropriate
ax.set_xlabel('Factors')
ax.set_ylabel('Number of endpoints')
ax.set_title('Standard vs Non-Standard Port Comparison for Australia')
ax.set_xticks(index + bar_width / 2)
ax.set_xticklabels(au_std_factors)
ax.legend()
plt.tight_layout()
plt.xticks(fontsize="small")

# Display text showing the total number of endpoints associated with the respective port types (std and non-std)
fig.text(0.19, 0.055, "Standard Port Totals: " + str(au_num_std_endpoints), ha="center", va="center")
fig.text(0.19, 0.025, "Non-standard Port Totals: " + str(au_num_non_std_endpoints), ha="center", va="center")

# Save the graph as a png 
plt.savefig("au_factor_support_by_port.png", dpi=300)


# Define variables for New Zealand used for plotting
nz_num_std_endpoints = len(nz_std_port_df)
nz_num_non_std_endpoints = len(nz_non_std_port_df)

nz_std_port_count = count_factors(nz_std_port_df)
nz_non_std_port_count = count_factors(nz_non_std_port_df)

nz_std_factors = list(nz_std_port_count.keys())
nz_std_counts = list(nz_std_port_count.values())

nz_non_std_factors = list(nz_non_std_port_count.keys())
nz_non_std_counts = list(nz_non_std_port_count.values())

# Update the counts lists to be relative (as a percentage) to the corresponding (std vs non-std) endpoint totals
nz_std_counts = [(count / nz_num_std_endpoints) * 100 for count in nz_std_counts]
nz_non_std_counts = [(count / nz_num_non_std_endpoints) * 100 for count in nz_non_std_counts]

# Setup for plotting 
n_groups = len(nz_std_counts)
index = np.arange(n_groups)
bar_width = 0.35
plt.figure(figsize=(17, 6))

# Plot the data comparing std vs non-std ports as a grouped bar graph
fig, ax = plt.subplots()
nz_std_bars = ax.bar(index, nz_std_counts, bar_width, label='Standard Port')
nz_non_std_bars = ax.bar(index + bar_width, nz_non_std_counts, bar_width, label='Non-standard Port')

# Add other details to the graph such as labels, and ensure the formatting/sizing is appropriate
ax.set_xlabel('Factors')
ax.set_ylabel('Number of endpoints')
ax.set_title('Standard vs Non-Standard Port Comparison for New Zealand')
ax.set_xticks(index + bar_width / 2)
ax.set_xticklabels(nz_std_factors)
ax.legend()
plt.tight_layout()
plt.xticks(fontsize="small")

# Display text showing the total number of endpoints associated with the respective port types (std and non-std)
fig.text(0.19, 0.055, "Standard Port Totals: " + str(nz_num_std_endpoints), ha="center", va="center")
fig.text(0.19, 0.025, "Non-standard Port Totals: " + str(nz_num_non_std_endpoints), ha="center", va="center")

# Save the graph as a png 
plt.savefig("nz_factor_support_by_port.png", dpi=300)


# Setup the combined bar plot/figure
n_groups = len(au_std_factors)
bar_width = 0.15 
opacity = 0.8

# Define the (relative) positions of the bars
index = np.arange(n_groups)
offset = bar_width

# Plot the data all on the same graph
plt.figure(figsize=(22, 8))
fig, ax = plt.subplots()

nz_std_bars = ax.bar(index - 1.5*offset, nz_std_counts, bar_width, alpha=opacity, label='NZ Standard')
au_std_bars = ax.bar(index - 0.5*offset, au_std_counts, bar_width, alpha=opacity, label='AU Standard')

nz_non_std_bars = ax.bar(index + 0.5*offset, nz_non_std_counts, bar_width, alpha=opacity, label='NZ Non-standard')
au_non_std_bars = ax.bar(index + 1.5*offset, au_non_std_counts, bar_width, alpha=opacity, label='AU Non-standard')

# Add other details such as labels, and ensure the formatting/sizing is appropriate
ax.set_xlabel('Factors')
ax.set_ylabel('Percentage of Corresponding Total Endpoints')
ax.set_title('Port Comparison by Type for Australia and New Zealand')
ax.set_xticks(index)
ax.set_xticklabels(au_std_factors)
ax.legend()
plt.xticks(fontsize="small")
plt.tight_layout()
plt.grid(axis='y')

# Save the combined AU NZ graph as a png
plt.savefig("combined_factor_support_by_port.png", dpi=300)