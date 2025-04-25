import csv
from collections import defaultdict

# Adjusted thresholds
LEV_THRESHOLD = 10       # Increased from 6
JACCARD_THRESHOLD = 0.35 # Decreased from 0.5
TOP_N = 5                # Increased from 3

def read_similarity_csv(filepath):
    results = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'phishing': row['Phishing Domain'],
                'legit': row['Legit Domain'],
                'lev': int(row['Levenshtein']),
                'jac': float(row['Jaccard']),
                # Add a combined score
                'combined': float(row['Jaccard']) - (int(row['Levenshtein']) / 20)
            })
    return results

def get_top_matches(similarity_data, top_n=5):
    phish_to_matches = defaultdict(list)

    for row in similarity_data:
        # Only exclude very dissimilar domains
        if row['jac'] < 0.1 and row['lev'] > 15:
            continue
        phish_to_matches[row['phishing']].append(row)

    filtered_results = []

    for phish, matches in phish_to_matches.items():
        # Sort primarily by combined score
        matches.sort(key=lambda x: (-x['combined'], x['lev'], -x['jac']))
        
        count = 0
        for match in matches:
            # More permissive filtering logic
            if (match['lev'] <= LEV_THRESHOLD or 
                match['jac'] >= JACCARD_THRESHOLD or
                match['combined'] > 0.2):  # New combined threshold
                filtered_results.append(match)
                count += 1
            if count == top_n:
                break

    return filtered_results

def write_filtered_csv(filtered_data, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'Phishing Domain', 'Legit Domain', 'Levenshtein', 'Jaccard', 'Combined Score'
        ])
        writer.writeheader()
        for row in filtered_data:
            writer.writerow({
                'Phishing Domain': row['phishing'],
                'Legit Domain': row['legit'],
                'Levenshtein': row['lev'],
                'Jaccard': row['jac'],
                'Combined Score': row['combined']
            })

if __name__ == "__main__":
    data = read_similarity_csv('data/similarity_scores.csv')
    top_matches = get_top_matches(data, TOP_N)
    write_filtered_csv(top_matches, 'data/filtered_matches.csv')
    print(f"Found {len(top_matches)} filtered matches")
    print(f"Representing {len(set([m['phishing'] for m in top_matches]))} unique phishing domains")
    print(f"Filtered matches saved to data/filtered_matches.csv")