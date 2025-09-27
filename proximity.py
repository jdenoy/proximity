#!/usr/bin/env python3
"""
Proximity - MCP Security Scanner
A tool for scanning and analyzing MCP servers with NOVA security evaluation.

Author: Thomas Roccia (@fr0gger_)
Version: 1.0.0
License: MIT
Repository: https://github.com/fr0gger/proximity

Proximity is a security-focused MCP server scanner that provides:
- MCP server discovery and analysis
- Tools, prompts, and resources enumeration
- Function signature analysis and documentation
- NOVA-based security evaluation
- Multiple output formats (console, JSON, markdown)
- Support for stdio, SSE, and HTTP transports

Usage:
    python proximity.py <target> [options]
    
Examples:
    # Basic scan
    python proximity.py http://localhost:8000
    
    # Security scan with Nova rules
    python proximity.py http://localhost:8000 --nova-scan -r my_rule.nov
    
    # Export detailed reports
    python proximity.py "python server.py" --json-report --md-report
"""

import argparse
import asyncio
import json
import sys
import os
from datetime import datetime
from typing import Optional

from mcp_scanner_lib import scan_mcp_server
from nova_evaluator_lib import NovaEvaluator, MCPNovaAnalyzer, NOVA_AVAILABLE
from yaspin import yaspin

TOOL_NAME = "Proximity"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR = "Thomas Roccia (@fr0gger_)"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ProximityReporter:
    """Reporter for generating output reports."""
    
    def __init__(self, results: dict, nova_analysis: Optional[dict] = None):
        self.results = results
        self.nova_analysis = nova_analysis
    
    def display_console_report(self):
        """Display a nice terminal report."""
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - MCP Security Scanner{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

        print(f"{CYAN}Target:{RESET} {self.results['target']}")
        scan_time = self.results['timestamp'][:19].replace('T', ' ')
        print(f"{CYAN}Scan Time:{RESET} {scan_time}")
        print(f"{CYAN}Endpoints:{RESET} {len(self.results['endpoints'])}")
        transport_types = ', '.join(self.results['transport_types'])
        print(f"{CYAN}Transport Types:{RESET} {transport_types}")

        caps = self.results["capabilities"]
        print(f"\n{BOLD}{YELLOW}[CONFIG] Server Capabilities:{RESET}")
        tools_status = f"{GREEN}[+] YES{RESET}" if caps.get('tools') else f"{RED}[-] NO{RESET}"
        prompts_status = f"{GREEN}[+] YES{RESET}" if caps.get('prompts') else f"{RED}[-] NO{RESET}"
        resources_status = f"{GREEN}[+] YES{RESET}" if caps.get('resources') else f"{RED}[-] NO{RESET}"

        print(f"  {CYAN}Tools:{RESET} {tools_status}")
        print(f"  {CYAN}Prompts:{RESET} {prompts_status}")
        print(f"  {CYAN}Resources:{RESET} {resources_status}")

        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            print(f"\n{BOLD}{BLUE}[TOOLS] Tools Discovered ({tool_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, tool in enumerate(self.results["tools"], 1):
                param_count = len(tool["parameters"])
                required_count = len([p for p in tool["parameters"]
                                     if p["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{tool['name']}{RESET}")
                print(f"   {CYAN}Description:{RESET} {tool['description']}")
                print(f"   {CYAN}Parameters:{RESET} {param_count} total "
                      f"({required_count} required)")
                complexity = tool['complexity'].title()
                if complexity == "Simple":
                    complexity_color = GREEN
                elif complexity == "Moderate":
                    complexity_color = YELLOW
                else:
                    complexity_color = RED
                print(f"   {CYAN}Complexity:{RESET} {complexity_color}{complexity}{RESET}")

                if tool["parameters"]:
                    print(f"   {CYAN}Function Parameters:{RESET}")
                    for param in tool["parameters"]:
                        marker = f"{RED}*{RESET}" if param["required"] else " "
                        print(f"     {marker} {BOLD}{param['name']}{RESET}: "
                              f"{param['type']}")
                        if param['description'] != "No description":
                            print(f"       {CYAN}Description:{RESET} "
                                  f"{param['description']}")

                    print(f"   {CYAN}Function Signature:{RESET} "
                          f"{BOLD}{tool['function_signature']}{RESET}")

                    if tool["example_usage"]:
                        print(f"   {CYAN}Example Usage:{RESET}")
                        for param, value in tool["example_usage"].items():
                            print(f"     {param}: \"{value}\"")

        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            print(f"\n{BOLD}{BLUE}[PROMPTS] Prompts Discovered ({prompt_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, prompt in enumerate(self.results["prompts"], 1):
                arg_count = len(prompt["arguments"])
                required_count = len([a for a in prompt["arguments"]
                                     if a["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{prompt['name']}{RESET}")
                print(f"   {CYAN}Description:{RESET} {prompt['description']}")
                print(f"   {CYAN}Arguments:{RESET} {arg_count} total "
                      f"({required_count} required)")

                if prompt["arguments"]:
                    print(f"   {CYAN}Parameters:{RESET}")
                    for arg in prompt["arguments"]:
                        marker = f"{RED}*{RESET}" if arg["required"] else " "
                        print(f"     {marker} {BOLD}{arg['name']}{RESET}: "
                              f"{arg['description']}")

                #full prompt content
                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    print(f"   {CYAN}Full Prompt Content:{RESET}")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        print(f"     {YELLOW}Message {msg_idx} ({role}):{RESET}")

                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item["text"]
                                # Show first 3 lines for console
                                lines = text.split('\n')[:3]
                                for line in lines:
                                    print(f"       {line}")
                                if len(text.split('\n')) > 3:
                                    remaining_lines = (len(text.split('\n'))
                                                      - 3)
                                    print(f"       {YELLOW}... ({remaining_lines} "
                                          f"more lines){RESET}")

        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            print(f"\n{BOLD}{BLUE}[RESOURCES] Resources Discovered ({resource_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, resource in enumerate(self.results["resources"], 1):
                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{resource['uri']}{RESET}")
                if resource["name"]:
                    print(f"   {CYAN}Name:{RESET} {resource['name']}")
                if resource["description"] != "No description":
                    print(f"   {CYAN}Description:{RESET} {resource['description']}")
                if resource["mime_type"]:
                    print(f"   {CYAN}MIME Type:{RESET} {resource['mime_type']}")

        if self.nova_analysis:
            self._display_nova_analysis()

        if self.results["errors"]:
            error_count = len(self.results['errors'])
            print(f"\n{BOLD}{RED}[ERROR] Errors Encountered ({error_count}){RESET}")
            print(f"{RED}{'-' * 50}{RESET}")
            for i, error in enumerate(self.results["errors"], 1):
                print(f"   {YELLOW}[{i}]{RESET} {RED}{error}{RESET}")

        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        summary_parts = []
        if self.results["tools"]:
            summary_parts.append(f"{len(self.results['tools'])} tools")
        if self.results["prompts"]:
            summary_parts.append(f"{len(self.results['prompts'])} prompts")
        if self.results["resources"]:
            summary_parts.append(f"{len(self.results['resources'])} "
                                "resources")

        summary = (", ".join(summary_parts) if summary_parts
                   else "No capabilities")
        print(f"{BOLD}{GREEN}[SUMMARY]{RESET} Discovery: {GREEN}{summary}{RESET}")

        if self.nova_analysis:
            flagged = self.nova_analysis["flagged_count"]
            total = self.nova_analysis["total_texts_analyzed"]
            rule_count = self.nova_analysis["rule_info"]["rule_count"]
            
            # Unique rules that matched
            matched_rules_set = set()
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):
                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    if matched_rules:
                        matched_rules_set.update(matched_rules)
                    else:
                        matched_rules_set.add(primary_rule)
            
            matched_rule_count = len(matched_rules_set)
            
            print(f"{BOLD}{GREEN}[SECURITY]{RESET} Analysis: {flagged}/{total} items flagged")
            if matched_rule_count > 0:
                print(f"{BOLD}{GREEN}[NOVA]{RESET} {matched_rule_count} rule{'s' if matched_rule_count > 1 else ''} matched")

        print(f"{BOLD}{CYAN}{'='*60}{RESET}")
    
    def _display_nova_analysis(self):
        """Display Nova security analysis results."""
        print(f"\n{BOLD}{GREEN}[NOVA] NOVA Analysis Results{RESET}")
        print(f"{GREEN}{'-' * 50}{RESET}")

        rule_info = self.nova_analysis["rule_info"]
        
        if rule_info['rule_count'] > 1:
            rules_str = ', '.join(rule_info['rule_names'])
            print(f"{CYAN}Rules:{RESET} {rules_str} ({rule_info['rule_count']} total)")
        else:
            print(f"{CYAN}Rule:{RESET} {rule_info['name']}")
        
        print(f"{CYAN}Evaluator:{RESET} {rule_info['evaluator_type']}")
        total_analyzed = self.nova_analysis['total_texts_analyzed']
        print(f"{CYAN}Total Items Analyzed:{RESET} {total_analyzed}")
        print(f"{CYAN}Flagged Items:{RESET} {self.nova_analysis['flagged_count']}")

        if self.nova_analysis["flagged_count"] > 0:
            print(f"\n{BOLD}{RED}[!] Security Alerts:{RESET}")
            
            alerts_by_rule = {}
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):

                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    
                    if not matched_rules:
                        matched_rules = [primary_rule]
                    
                    # Add this result to each rule it matches
                    for rule_name in matched_rules:
                        if rule_name not in alerts_by_rule:
                            alerts_by_rule[rule_name] = []
                        alerts_by_rule[rule_name].append(result)
            
            # alerts grouped by rule
            for rule_name, alerts in alerts_by_rule.items():
                print(f"\n{BOLD}{RED}▌ Rule: {rule_name} ({len(alerts)} alert{'s' if len(alerts) > 1 else ''}){RESET}")
                print(f"{RED}{'─' * 50}{RESET}")
                
                for i, result in enumerate(alerts, 1):
                    nova_result = result["nova_evaluation"]
                    
                    print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{result['source']}{RESET}")
                    print(f"    {CYAN}Type:{RESET} {result['type']}")
                    print(f"    {CYAN}Content:{RESET} {result['text_preview']}")
                    
                    # matched keywords specific to this rule
                    per_rule_keywords = nova_result.get("per_rule_keywords", {})
                    
                    # keywords for the current rule displaying
                    if per_rule_keywords and rule_name in per_rule_keywords:
                        keywords_to_show = per_rule_keywords[rule_name]
                    else:
                        keywords_to_show = nova_result.get("matching_keywords", {})
                    
                    if keywords_to_show:
                        if isinstance(keywords_to_show, dict):
                            keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                        else:
                            keyword_list = [str(keywords_to_show)]
                        
                        if keyword_list:
                            keywords_str = ", ".join(keyword_list)
                            print(f"    {CYAN}Triggered Keywords:{RESET} {keywords_str}")
                    
                    matched_rules = nova_result.get("matched_rules", [])
                    if matched_rules and len(matched_rules) > 1:
                        other_rules = [r for r in matched_rules if r != rule_name]
                        if other_rules:
                            print(f"    {CYAN}Also Matches:{RESET} {', '.join(other_rules)}")
        else:
            print(f"\n{GREEN}[+] No security issues detected!{RESET}")
    
    def export_json_report(self, filename: str):
        """Export detailed JSON report."""
        report = {
            "scan_results": self.results,
            "nova_analysis": self.nova_analysis,
            "export_timestamp": datetime.now().isoformat()
        }
        
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{GREEN}[+] JSON report exported to: {filename}{RESET}")

    def export_markdown_report(self, filename: str):
        """Export markdown report."""
        md_content = []

        # Header
        header = f"# {TOOL_NAME} v{TOOL_VERSION} - MCP Security Scan Report\n\n"
        md_content.append(header)
        md_content.append(f"**Target:** {self.results['target']}\n")
        md_content.append(f"**Scan Date:** {self.results['timestamp']}\n")
        md_content.append(f"**Endpoints:** {len(self.results['endpoints'])}\n")
        transport_types = ', '.join(self.results['transport_types'])
        md_content.append(f"**Transport Types:** {transport_types}\n\n")

        # Capabilities
        caps = self.results["capabilities"]
        md_content.append("## Server Capabilities\n\n")
        tools_status = '✅ Available' if caps.get('tools') else '❌ Not Available'
        prompts_status = ('✅ Available' if caps.get('prompts')
                         else '❌ Not Available')
        resources_status = ('✅ Available' if caps.get('resources')
                           else '❌ Not Available')
        md_content.append(f"- **Tools:** {tools_status}\n")
        md_content.append(f"- **Prompts:** {prompts_status}\n")
        md_content.append(f"- **Resources:** {resources_status}\n\n")
        
        # Tools
        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            md_content.append(f"## Tools Analysis ({tool_count} found)\n\n")
            for tool in self.results["tools"]:
                md_content.append(f"### {tool['name']}\n\n")
                md_content.append(f"**Description:** {tool['description']}\n\n")
                complexity = tool['complexity'].title()
                md_content.append(f"**Complexity:** {complexity}\n")
                param_count = len(tool['parameters'])
                md_content.append(f"**Parameters:** {param_count} total\n\n")

                if tool["parameters"]:
                    md_content.append("**Function Parameters:**\n")
                    for param in tool["parameters"]:
                        status = "Required" if param["required"] else "Optional"
                        param_desc = param['description']
                        md_content.append(f"- `{param['name']}` "
                                        f"({param['type']}, {status}): "
                                        f"{param_desc}\n")
                    md_content.append("\n")
                    signature = tool['function_signature']
                    md_content.append(f"**Function Signature:**\n"
                                    f"```\n{signature}\n```\n\n")

        # Prompts
        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            md_content.append(f"## Prompts Analysis ({prompt_count} found)\n\n")
            for prompt in self.results["prompts"]:
                md_content.append(f"### {prompt['name']}\n\n")
                md_content.append(f"**Description:** {prompt['description']}\n\n")

                if prompt["arguments"]:
                    md_content.append("**Arguments:**\n")
                    for arg in prompt["arguments"]:
                        status = "Required" if arg["required"] else "Optional"
                        md_content.append(f"- `{arg['name']}` ({status}): "
                                        f"{arg['description']}\n")
                    md_content.append("\n")

                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    md_content.append("**Full Prompt Content:**\n")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        md_content.append(f"**Message {msg_idx} ({role}):**\n")
                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item['text']
                                md_content.append(f"```\n{text}\n```\n\n")

        # Resources
        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            md_content.append(f"## Resources Analysis "
                            f"({resource_count} found)\n\n")
            for resource in self.results["resources"]:
                md_content.append(f"### {resource['uri']}\n\n")
                if resource["name"]:
                    md_content.append(f"**Name:** {resource['name']}\n")
                md_content.append(f"**Description:** "
                                f"{resource['description']}\n")
                if resource["mime_type"]:
                    md_content.append(f"**MIME Type:** "
                                    f"{resource['mime_type']}\n")
                md_content.append("\n")

        # Nova analysis
        if self.nova_analysis:
            md_content.append("## Security Analysis\n\n")
            rule_info = self.nova_analysis["rule_info"]
            
            # Show all rules if multiple rules are loaded
            if rule_info['rule_count'] > 1:
                rules_str = ', '.join(rule_info['rule_names'])
                md_content.append(f"**Rules:** {rules_str} ({rule_info['rule_count']} total)\n")
            else:
                md_content.append(f"**Rule:** {rule_info['name']}\n")
            
            md_content.append(f"**Evaluator:** "
                            f"{rule_info['evaluator_type']}\n")
            total_analyzed = self.nova_analysis['total_texts_analyzed']
            md_content.append(f"**Items Analyzed:** {total_analyzed}\n")
            flagged_count = self.nova_analysis['flagged_count']
            md_content.append(f"**Flagged Items:** {flagged_count}\n\n")

            if self.nova_analysis["flagged_count"] > 0:
                md_content.append("### Security Alerts\n\n")
                
                alerts_by_rule = {}
                for result in self.nova_analysis["analysis_results"]:
                    if result["nova_evaluation"].get("matched", False):
                        matched_rules = result["nova_evaluation"].get("matched_rules", [])
                        primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                        
                        if not matched_rules:
                            matched_rules = [primary_rule]
                        
                        for rule_name in matched_rules:
                            if rule_name not in alerts_by_rule:
                                alerts_by_rule[rule_name] = []
                            alerts_by_rule[rule_name].append(result)
                
                for rule_name, alerts in alerts_by_rule.items():
                    alert_count = len(alerts)
                    md_content.append(f"#### Rule: {rule_name} ({alert_count} alert{'s' if alert_count > 1 else ''})\n\n")
                    
                    for i, result in enumerate(alerts, 1):
                        nova_result = result["nova_evaluation"]
                        
                        md_content.append(f"**[{i}] {result['source']}**\n\n")
                        md_content.append(f"- **Type:** {result['type']}\n")
                        md_content.append(f"- **Content:** {result['text_preview']}\n")
                        
                        per_rule_keywords = nova_result.get("per_rule_keywords", {})
                        
                        if per_rule_keywords and rule_name in per_rule_keywords:
                            keywords_to_show = per_rule_keywords[rule_name]
                        else:
                            keywords_to_show = nova_result.get("matching_keywords", {})
                        
                        if keywords_to_show:
                            if isinstance(keywords_to_show, dict):
                                keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                            else:
                                keyword_list = [str(keywords_to_show)]
                            
                            if keyword_list:
                                keywords_str = ", ".join(keyword_list)
                                md_content.append(f"- **Triggered Keywords:** {keywords_str}\n")
                        
                        # Show additional matched rules if multiple rules matched
                        matched_rules = nova_result.get("matched_rules", [])
                        if matched_rules and len(matched_rules) > 1:
                            other_rules = [r for r in matched_rules if r != rule_name]
                            if other_rules:
                                md_content.append(f"- **Also Matches:** {', '.join(other_rules)}\n")
                        
                        md_content.append("\n")

        # Errors
        if self.results["errors"]:
            md_content.append("## Errors\n\n")
            for error in self.results["errors"]:
                md_content.append(f"- {error}\n")
            md_content.append("\n")

        # Write to file
        with open(filename, "w") as f:
            f.write("".join(md_content))

        print(f"{GREEN}[+] Markdown report exported to: {filename}{RESET}")


def print_ascii_art():
    """Print fun ASCII art for help display."""
    art = """
    ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███╗   ███╗██╗████████╗██╗   ██╗
    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██║████╗ ████║██║╚══██╔══╝╚██╗ ██╔╝
    ██████╔╝██████╔╝██║   ██║ ╚███╔╝ ██║██╔████╔██║██║   ██║    ╚████╔╝ 
    ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ██║██║╚██╔╝██║██║   ██║     ╚██╔╝  
    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗██║██║ ╚═╝ ██║██║   ██║      ██║   
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝      ╚═╝   
    
    🛡️  MCP Security Scanner v{} - by {}
    🔍 Discover • 🔧 Analyze • 🛡️  Secure
    """.format(TOOL_VERSION, TOOL_AUTHOR)
    print(art)


class CustomHelpAction(argparse._HelpAction):
    """Custom help action that shows ASCII art."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest, default, help)

    def __call__(self, parser, namespace, values, option_string=None):
        _ = namespace, values, option_string
        print_ascii_art()
        parser.print_help()
        parser.exit()


async def main():
    """Main function for Proximity scanner."""
    parser = argparse.ArgumentParser(
        description="Proximity - MCP Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  
        epilog="""
Examples:
  # Basic MCP scan
  python proximity.py http://localhost:8000

  # Scan with authentication
  python proximity.py http://localhost:8000 -t your_token

  # Scan stdio server
  python proximity.py "python server.py"

  # Security scan with Nova rules
  python proximity.py http://localhost:8000 -n -r my_rule.nov
  python proximity.py http://localhost:8000 --nova-scan -r my_rule.nov

  # Export reports
  python proximity.py http://localhost:8000 --json-report --md-report
        """
    )
    
    parser.add_argument('-h', '--help', action=CustomHelpAction,
                        help='show this help message and exit')

    # Required arguments
    parser.add_argument("target",
                        help="MCP server target (HTTP URL or stdio command)")

    parser.add_argument("-t", "--token",
                        help="Authentication token for HTTP endpoints")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output during scanning")

    # Nova security scanning
    nova_group = parser.add_argument_group("Nova Security Scanning")
    nova_group.add_argument("-n", "--nova-scan", action="store_true",
                            help="Enable Nova security analysis")
    nova_group.add_argument("-r", "--rule", default="my_rule.nov",
                            help="Nova rule file path (default: my_rule.nov)")
    nova_group.add_argument("--evaluator", choices=["openai", "groq"],
                            default="openai",
                            help="LLM evaluator type (default: openai)")
    nova_group.add_argument("--model",
                            help="LLM model to use (optional)")
    nova_group.add_argument("--api-key",
                            help="API key for LLM evaluator (optional)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--json-report", action="store_true",
                              help="Export detailed JSON report")
    output_group.add_argument("--md-report", action="store_true",
                              help="Export markdown report")
    output_group.add_argument("--output-prefix", default="proximity_scan",
                              help="Prefix for output files "
                                   "(default: proximity_scan)")
    
    args = parser.parse_args()
    
    # Validate Nova requirements
    if args.nova_scan and not NOVA_AVAILABLE:
        print(f"{RED}[-] Error: Nova library not available for security scanning.{RESET}")
        print("Install with: pip install nova-hunting")
        sys.exit(1)
    
    if args.nova_scan and not os.path.exists(args.rule):
        print(f"{RED}[-] Error: Nova rule file not found: {args.rule}{RESET}")
        sys.exit(1)
    
    print(f"\n--==[{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - MCP Security Scanner{RESET} - {CYAN}by {TOOL_AUTHOR}{RESET}]==--")

    print(f"\n🎯 {CYAN}Target: {args.target}{RESET}")
    if args.nova_scan:
        print(f"🛡️ {YELLOW} NOVA Analysis: Enabled ({args.rule}){RESET}")
    print()
    
    try:
        with yaspin(text=" Scanning MCP server...", color="cyan") as spinner:
            await asyncio.sleep(0.1)
            verbose_mode = args.verbose or args.nova_scan
            
            def update_spinner(message):
                spinner.text = message
            
            scan_results = await scan_mcp_server(
                target=args.target,
                token=args.token,
                timeout=args.timeout,
                verbose=verbose_mode,
                spinner_callback=update_spinner
            )
            
            await asyncio.sleep(0.1)
            spinner.ok("[+]")
        
        if args.verbose:
            print(f"{CYAN}[DEBUG] Scan results summary:{RESET}")
            print(f"  Tools: {len(scan_results.get('tools', []))}")
            print(f"  Prompts: {len(scan_results.get('prompts', []))}")
            print(f"  Resources: {len(scan_results.get('resources', []))}")
            print(f"  Capabilities: {scan_results.get('capabilities', {})}")
        
        nova_analysis = None
        
        if args.nova_scan:
            with yaspin(text=" Running NOVA analysis...", 
                       color="yellow") as spinner:
                try:
                    # Setup Nova evaluator
                    nova_evaluator = NovaEvaluator(
                        rule_file_path=args.rule,
                        evaluator_type=args.evaluator,
                        model=args.model,
                        api_key=args.api_key
                    )
                    
                    analyzer = MCPNovaAnalyzer(nova_evaluator)
                    
                    def progress_callback(current, total, item):
                        spinner.text = (f" Analyzing {current}/{total}: "
                                       f"{item[:30]}...")
                    
                    nova_analysis = analyzer.analyze_mcp_results(
                        scan_results,
                        progress_callback=progress_callback
                    )
                    
                    flagged = nova_analysis['flagged_count']
                    total = nova_analysis['total_texts_analyzed']
                    spinner.ok(f"[+] NOVA analysis complete: "
                              f"{flagged}/{total} items flagged")
                    
                except Exception as e:
                    spinner.fail(f"[-] NOVA analysis failed: {e}")
                    nova_analysis = None
        
        reporter = ProximityReporter(scan_results, nova_analysis)
        
        reporter.display_console_report()
        
        if args.json_report or args.md_report:
            with yaspin(text=" Generating reports...",
                       color="green") as spinner:
                
                if args.json_report:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    json_filename = f"{args.output_prefix}_{timestamp}.json"
                    reporter.export_json_report(json_filename)
                
                if args.md_report:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    md_filename = f"{args.output_prefix}_{timestamp}.md"
                    reporter.export_markdown_report(md_filename)
                
                spinner.ok("[+]")
        
        print(f"\n{GREEN}[+] {TOOL_NAME} scan completed successfully!{RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[-] Scan failed: {e}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())