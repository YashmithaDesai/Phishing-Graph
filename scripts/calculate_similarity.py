import Levenshtein
import csv
import heapq

def jaccard_similarity(str1, str2, n=3):
    def ngrams(string, n):
        return set(string[i:i+n] for i in range(len(string)-n+1))
    ngrams1, ngrams2 = ngrams(str1, n), ngrams(str2, n)
    intersection = ngrams1 & ngrams2
    union = ngrams1 | ngrams2
    return len(intersection) / len(union) if union else 0

def load_domains(filename, limit=None):
    with open(filename, 'r') as file:
        domains = [line.strip() for line in file]
        return domains[:limit] if limit else domains

def get_top_matches(phish_domain, legit_domains, top_n=3):
    heap = []
    for legit in legit_domains:
        lev = Levenshtein.distance(phish_domain, legit)
        jac = jaccard_similarity(phish_domain, legit)
        # We use negative Jaccard because heapq is a min-heap
        heapq.heappush(heap, (lev, -jac, phish_domain, legit))
    return heapq.nsmallest(top_n, heap)

def main(phish_file, legit_file, output_csv, legit_chunk_size=10000, top_n=3):
    phishing_domains = load_domains(phish_file)
    legit_domains = load_domains(legit_file)  # Or stream this in parts if RAM is an issue

    with open(output_csv, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Phishing Domain', 'Legit Domain', 'Levenshtein', 'Jaccard'])

        for phish in phishing_domains:
            top_matches = get_top_matches(phish, legit_domains, top_n=top_n)
            for lev, neg_jac, phish_dom, legit_dom in top_matches:
                writer.writerow([phish_dom, legit_dom, lev, -neg_jac])

if __name__ == '__main__':
    main('data/phishing_domains.txt', 'data/legit_domains.txt', 'data/top_matches.csv')
