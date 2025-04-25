from neo4j import GraphDatabase
import csv
import os
from datetime import datetime

class Neo4jGraphBuilder:
    def __init__(self, uri, username, password):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def close(self):
        self.driver.close()

    def clear_database(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            print("Database cleared")

    def create_domain_nodes(self, phishing_domains, legit_domains):
        with self.driver.session() as session:
            # Create legitimate domain nodes
            for domain in legit_domains:
                result = session.run(
                    """
                    MERGE (d:Domain {name: $domain})
                    SET d.type = 'legitimate', d.created = datetime()
                    RETURN d
                    """,
                    domain=domain
                )
                print(f"Created legitimate domain: {domain}")
            
            # Create phishing domain nodes
            for domain in phishing_domains:
                result = session.run(
                    """
                    MERGE (d:Domain {name: $domain})
                    SET d.type = 'suspicious', d.created = datetime()
                    RETURN d
                    """,
                    domain=domain
                )
                print(f"Created suspicious domain: {domain}")

    def create_similarity_relationships(self, similarity_data):
        with self.driver.session() as session:
            for record in similarity_data:
                phish = record['phishing']
                legit = record['legit']
                lev = record['lev']
                jac = record['jac']
                combined = record.get('combined', jac - (lev / 20))  # Fallback if not provided
                
                session.run(
                    """
                    MATCH (p:Domain {name: $phish}), (l:Domain {name: $legit})
                    MERGE (p)-[r:SIMILAR_TO]->(l)
                    SET r.levenshtein = $lev, 
                        r.jaccard = $jac,
                        r.combinedScore = $combined,
                        r.created = datetime()
                    RETURN r
                    """,
                    phish=phish, legit=legit, lev=lev, jac=jac, combined=combined
                )
            print(f"Created {len(similarity_data)} similarity relationships")

    def add_ip_and_asn_data(self, domain_ip_mapping, ip_asn_mapping):
        """
        Add IP and ASN information to the graph
        
        domain_ip_mapping: dict of {domain: [ip_addresses]}
        ip_asn_mapping: dict of {ip: {'asn': asn_number, 'org': organization}}
        """
        with self.driver.session() as session:
            # Create IP nodes and relationships
            for domain, ips in domain_ip_mapping.items():
                for ip in ips:
                    # Create IP node if it doesn't exist
                    session.run(
                        """
                        MERGE (i:IPAddress {ip: $ip})
                        """,
                        ip=ip
                    )
                    
                    # Create relationship between domain and IP
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain}), (i:IPAddress {ip: $ip})
                        MERGE (d)-[r:RESOLVES_TO]->(i)
                        SET r.created = datetime()
                        """,
                        domain=domain, ip=ip
                    )
            
            # Create ASN nodes and relationships
            for ip, asn_info in ip_asn_mapping.items():
                asn = asn_info.get('asn')
                org = asn_info.get('org')
                
                if asn:
                    # Create ASN node
                    session.run(
                        """
                        MERGE (a:AutonomousSystem {asn: $asn})
                        ON CREATE SET a.organization = $org
                        """,
                        asn=asn, org=org
                    )
                    
                    # Link IP to ASN
                    session.run(
                        """
                        MATCH (i:IPAddress {ip: $ip}), (a:AutonomousSystem {asn: $asn})
                        MERGE (i)-[r:BELONGS_TO]->(a)
                        """,
                        ip=ip, asn=asn
                    )

    def add_whois_data(self, domain_whois_data):
        """
        Add WHOIS information to domain nodes
        
        domain_whois_data: dict of {domain: {'registrar': name, 'created': date, ...}}
        """
        with self.driver.session() as session:
            for domain, whois_data in domain_whois_data.items():
                # Add WHOIS properties to domain node
                properties = {
                    'domain': domain,
                    'registrar': whois_data.get('registrar'),
                    'creation_date': whois_data.get('creation_date'),
                    'expiration_date': whois_data.get('expiration_date'),
                    'last_updated': whois_data.get('updated_date'),
                    'registrant_org': whois_data.get('registrant_org')
                }
                
                # Filter out None values
                clean_props = {k: v for k, v in properties.items() if v is not None}
                
                # Convert any datetime objects to strings
                for k, v in clean_props.items():
                    if isinstance(v, datetime):
                        clean_props[k] = v.isoformat()
                
                # Create WHOIS properties
                cypher_sets = ", ".join([f"d.whois_{k} = ${k}" for k in clean_props.keys() if k != 'domain'])
                if cypher_sets:
                    session.run(
                        f"""
                        MATCH (d:Domain {{name: $domain}})
                        SET {cypher_sets}
                        """,
                        **clean_props
                    )
                
                # Create Organization node if it exists
                org = whois_data.get('registrant_org')
                if org:
                    session.run(
                        """
                        MERGE (o:Organization {name: $org})
                        WITH o
                        MATCH (d:Domain {name: $domain})
                        MERGE (d)-[r:REGISTERED_BY]->(o)
                        """,
                        domain=domain, org=org
                    )

def load_domains(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

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
                'combined': float(row.get('Combined Score', 0)) if 'Combined Score' in row else 
                            float(row['Jaccard']) - (int(row['Levenshtein']) / 20)
            })
    return results

if __name__ == "__main__":
    # Neo4j connection settings (update these)
    URI = "bolt://localhost:7687"
    USERNAME = "neo4j"
    PASSWORD = "phishingdb"

    builder = Neo4jGraphBuilder(URI, USERNAME, PASSWORD)
    
    # Clear existing data (optional)
    builder.clear_database()
    
    # Load domain data
    phishing_domains = load_domains('data/phishing_domains.txt')
    legit_domains = load_domains('data/legit_domains.txt')
    
    # Create domain nodes
    builder.create_domain_nodes(phishing_domains, legit_domains)
    
    # Load and create similarity relationships
    similarity_data = read_similarity_csv('data/filtered_matches.csv')
    builder.create_similarity_relationships(similarity_data)
    
    # Sample IP and ASN data (in a real implementation, you'd gather this data)
    # This would come from DNS lookups and IP geolocation/ASN services
    sample_domain_ip = {
        'google.com': ['142.250.185.78', '142.250.72.110'],
        'g00gle.com': ['103.224.182.248']
    }
    
    sample_ip_asn = {
        '142.250.185.78': {'asn': '15169', 'org': 'Google LLC'},
        '142.250.72.110': {'asn': '15169', 'org': 'Google LLC'},
        '103.224.182.248': {'asn': '133480', 'org': 'Intergrid Group Pty Ltd'}
    }
    
    # Add IP and ASN data
    # In production, you'd replace this with real data
    # builder.add_ip_and_asn_data(sample_domain_ip, sample_ip_asn)
    
    print("Neo4j graph database successfully built!")
    builder.close()