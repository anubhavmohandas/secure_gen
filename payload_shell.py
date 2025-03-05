import os
import sys
import cmd
from colorama import init, Fore, Style
from payload_generator import AdvancedPayloadGenerator, display_vulnerabilities

class PayloadGeneratorShell(cmd.Cmd):
    intro = f"""\n{Fore.GREEN}
╔══════════════════════════════════════════════════╗
║   🛡️  Secure Gen Payload Generator Shell 🔒    ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}
Type 'help' or '?' to list commands.\n"""
    
    prompt = f"{Fore.CYAN}secure-gen-shell> {Style.RESET_ALL}"

    def __init__(self):
        super().__init__()
        self.generator = AdvancedPayloadGenerator()
        init(autoreset=True)  # Initialize colorama

    def do_generate_passwords(self, arg):
        """Generate password payloads. Usage: generate_passwords firstname lastname birthdate"""
        args = arg.split()
        if len(args) < 3:
            print(f"{Fore.RED}Error: Provide firstname, lastname, and birthdate{Style.RESET_ALL}")
            return

        personal_info = {
            'first_name': args[0],
            'last_name': args[1],
            'birthdate': args[2],
            'pet_name': '',
            'company': ''
        }

        payloads = self.generator.generate_advanced_password_payloads(personal_info)
        print(f"\n{Fore.GREEN}Generated {len(payloads)} Password Payloads:{Style.RESET_ALL}")
        for payload in payloads[:20]:  # Limit display to first 20
            print(payload)

    def do_generate_sql(self, arg):
        """Generate SQL Injection payloads"""
        payloads = self.generator.generate_advanced_sql_injection()
        print(f"\n{Fore.GREEN}Generated {len(payloads)} SQL Injection Payloads:{Style.RESET_ALL}")
        for payload in payloads:
            print(payload)

    def do_generate_rce(self, arg):
        """Generate Remote Code Execution payloads"""
        payloads = self.generator.generate_advanced_rce_payloads()
        print(f"\n{Fore.GREEN}Generated {len(payloads)} RCE Payloads:{Style.RESET_ALL}")
        for payload in payloads:
            print(payload)

    def do_vulnerabilities(self, arg):
        """Display vulnerability landscape"""
        print(display_vulnerabilities())

    def do_report(self, arg):
        """Generate comprehensive payload report"""
        report = self.generator.generate_comprehensive_report()
        print(f"\n{Fore.GREEN}Report Generated. Total Payloads: {report['total_payloads']}{Style.RESET_ALL}")
        print(f"Check 'payload_generation_report.json' for details.")

    def do_exit(self, arg):
        """Exit the shell"""
        print(f"\n{Fore.YELLOW}Exiting Secure Gen Payload Generator Shell.{Style.RESET_ALL}")
        return True

    # Alias for exit
    do_quit = do_exit

def main():
    shell = PayloadGeneratorShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Shell terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()