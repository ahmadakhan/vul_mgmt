export interface CatalogProduct {
  name: string;
  normalizedId: string;
  part: 'a' | 'o' | 'h';
  defaultVersion?: string;
  description: string;
  defaultPurl?: string;
}

export interface CatalogVendor {
  name: string;
  normalizedId: string;
  aliases: string[];
  products: CatalogProduct[];
}

export const ENTERPRISE_VENDOR_CATALOG: CatalogVendor[] = [
  {
    name: 'Microsoft',
    normalizedId: 'microsoft',
    aliases: ['msft', 'microsoft_corp', 'microsoft_corporation'],
    products: [
      {
        name: 'Windows Server 2025',
        normalizedId: 'windows_server_2025',
        part: 'o',
        description: 'Enterprise Server Operating System',
      },
      {
        name: 'Windows Server 2022',
        normalizedId: 'windows_server_2022',
        part: 'o',
        description: 'Enterprise Server Operating System',
      },
      {
        name: 'Windows Server 2019',
        normalizedId: 'windows_server_2019',
        part: 'o',
        description: 'Enterprise Server Operating System',
      },
      {
        name: 'Windows 11',
        normalizedId: 'windows_11',
        part: 'o',
        description: 'Enterprise Client Operating System',
      },
      {
        name: 'Windows 10',
        normalizedId: 'windows_10',
        part: 'o',
        description: 'Enterprise Client Operating System',
      },
      {
        name: 'Exchange Server',
        normalizedId: 'exchange_server',
        part: 'a',
        description: 'Enterprise Mail and Messaging Server',
      },
      {
        name: 'SQL Server',
        normalizedId: 'sql_server',
        part: 'a',
        description: 'Relational Database Management System',
      },
      {
        name: 'SharePoint Server',
        normalizedId: 'sharepoint_server',
        part: 'a',
        description: 'Intranet and Collaboration Platform',
      },
      {
        name: 'Microsoft Edge',
        normalizedId: 'edge',
        part: 'a',
        description: 'Chromium-based Enterprise Browser',
      },
      {
        name: 'Office 365 Apps',
        normalizedId: 'office_365',
        part: 'a',
        description: 'Enterprise Productivity Suite',
      },
      {
        name: 'Defender for Endpoint',
        normalizedId: 'defender_endpoint',
        part: 'a',
        description: 'EDR Agent & Endpoint Security',
      },
      {
        name: 'Internet Information Services (IIS)',
        normalizedId: 'iis',
        part: 'a',
        description: 'Web Server Services',
      },
      {
        name: 'Azure DevOps Server',
        normalizedId: 'azure_devops_server',
        part: 'a',
        description: 'On-premises CI/CD and Version Control',
      },
    ],
  },
  {
    name: 'Cisco',
    normalizedId: 'cisco',
    aliases: ['cisco_systems', 'cisco-systems'],
    products: [
      {
        name: 'IOS XE Software',
        normalizedId: 'ios_xe',
        part: 'o',
        description: 'Modular Enterprise Routing & Switching OS',
      },
      {
        name: 'IOS Software',
        normalizedId: 'ios',
        part: 'o',
        description: 'Enterprise Network Operating System',
      },
      {
        name: 'NX-OS Software',
        normalizedId: 'nx-os',
        part: 'o',
        description: 'Data Center Switch Operating System',
      },
      {
        name: 'Adaptive Security Appliance (ASA)',
        normalizedId: 'adaptive_security_appliance_software',
        part: 'o',
        description: 'Security Appliance and Firewall OS',
      },
      {
        name: 'Firepower Threat Defense (FTD)',
        normalizedId: 'firepower_threat_defense',
        part: 'o',
        description: 'Unified NGFW Software',
      },
      {
        name: 'AnyConnect Secure Mobility Client',
        normalizedId: 'anyconnect_secure_mobility_client',
        part: 'a',
        description: 'Enterprise VPN Client',
      },
      {
        name: 'Catalyst 9000 Switches',
        normalizedId: 'catalyst_9000',
        part: 'h',
        description: 'Enterprise Core & Access Switches',
      },
      {
        name: 'Webex Meetings Client',
        normalizedId: 'webex_meetings',
        part: 'a',
        description: 'Collaboration & Video Conferencing Client',
      },
    ],
  },
  {
    name: 'Fortinet',
    normalizedId: 'fortinet',
    aliases: ['fortigate', 'fortios'],
    products: [
      {
        name: 'FortiOS',
        normalizedId: 'fortios',
        part: 'o',
        description: 'Next-Generation Firewall Operating System',
      },
      {
        name: 'FortiGate NGFW',
        normalizedId: 'fortigate',
        part: 'h',
        description: 'Enterprise Network Security Appliance',
      },
      {
        name: 'FortiClient',
        normalizedId: 'forticlient',
        part: 'a',
        description: 'Endpoint Telemetry & Zero Trust Client',
      },
      {
        name: 'FortiAnalyzer',
        normalizedId: 'fortianalyzer',
        part: 'a',
        description: 'Centralized Logging and Analytics',
      },
      {
        name: 'FortiManager',
        normalizedId: 'fortimanager',
        part: 'a',
        description: 'Centralized Network Management',
      },
      {
        name: 'FortiWeb',
        normalizedId: 'fortiweb',
        part: 'a',
        description: 'Web Application Firewall (WAF)',
      },
      {
        name: 'FortiMail',
        normalizedId: 'fortimail',
        part: 'a',
        description: 'Secure Email Gateway Appliance',
      },
    ],
  },
  {
    name: 'VMware / Broadcom',
    normalizedId: 'vmware',
    aliases: ['broadcom', 'vmware_inc'],
    products: [
      {
        name: 'ESXi Hypervisor',
        normalizedId: 'esxi',
        part: 'o',
        description: 'Type-1 Bare-Metal Hypervisor',
      },
      {
        name: 'vCenter Server',
        normalizedId: 'vcenter_server',
        part: 'a',
        description: 'Centralized Hypervisor Management',
      },
      {
        name: 'Horizon Client & Server',
        normalizedId: 'horizon',
        part: 'a',
        description: 'Virtual Desktop Infrastructure (VDI)',
      },
      {
        name: 'Spring Framework',
        normalizedId: 'spring_framework',
        part: 'a',
        defaultPurl: 'pkg:maven/org.springframework/spring-core',
        description: 'Java Enterprise Application Framework',
      },
      {
        name: 'Cloud Foundation',
        normalizedId: 'cloud_foundation',
        part: 'a',
        description: 'Hybrid Cloud Infrastructure Platform',
      },
      {
        name: 'Tanzu Kubernetes Grid',
        normalizedId: 'tanzu_kubernetes_grid',
        part: 'a',
        description: 'Enterprise Kubernetes Platform',
      },
      {
        name: 'Workstation Pro',
        normalizedId: 'workstation_pro',
        part: 'a',
        description: 'Desktop Virtualization Software',
      },
    ],
  },
  {
    name: 'Palo Alto Networks',
    normalizedId: 'paloaltonetworks',
    aliases: ['palo_alto', 'paloalto', 'pan'],
    products: [
      {
        name: 'PAN-OS',
        normalizedId: 'pan-os',
        part: 'o',
        description: 'Next-Generation Firewall Operating System',
      },
      {
        name: 'GlobalProtect',
        normalizedId: 'globalprotect',
        part: 'a',
        description: 'Enterprise Secure Access & VPN',
      },
      {
        name: 'Prisma Cloud',
        normalizedId: 'prisma_cloud',
        part: 'a',
        description: 'Cloud Native Application Protection (CNAPP)',
      },
      {
        name: 'Cortex XDR Agent',
        normalizedId: 'cortex_xdr',
        part: 'a',
        description: 'Extended Detection and Response Agent',
      },
      {
        name: 'PA-Series Hardware',
        normalizedId: 'pa-series',
        part: 'h',
        description: 'Enterprise Physical Security Appliance',
      },
    ],
  },
  {
    name: 'Apache Software Foundation',
    normalizedId: 'apache',
    aliases: ['apache_software_foundation', 'asf'],
    products: [
      {
        name: 'HTTP Server',
        normalizedId: 'http_server',
        part: 'a',
        description: 'High Performance Open Source Web Server',
      },
      {
        name: 'Tomcat Servlet Engine',
        normalizedId: 'tomcat',
        part: 'a',
        description: 'Java Servlet and JSP Application Server',
      },
      {
        name: 'Log4j Logging Library',
        normalizedId: 'log4j',
        part: 'a',
        defaultPurl: 'pkg:maven/org.apache.logging.log4j/log4j-core',
        description: 'Java Logging Framework',
      },
      {
        name: 'Struts Framework',
        normalizedId: 'struts',
        part: 'a',
        defaultPurl: 'pkg:maven/org.apache.struts/struts2-core',
        description: 'Java Web Application MVC Framework',
      },
      { name: 'ActiveMQ', normalizedId: 'activemq', part: 'a', description: 'Open Source Message Broker' },
      {
        name: 'Kafka',
        normalizedId: 'kafka',
        part: 'a',
        description: 'Distributed Event Streaming Platform',
      },
      { name: 'Airflow', normalizedId: 'airflow', part: 'a', description: 'Workflow Orchestration Platform' },
    ],
  },
  {
    name: 'Red Hat',
    normalizedId: 'redhat',
    aliases: ['red_hat', 'redhat_corp'],
    products: [
      {
        name: 'Enterprise Linux (RHEL)',
        normalizedId: 'enterprise_linux',
        part: 'o',
        description: 'Enterprise Linux Server Distribution',
      },
      {
        name: 'OpenShift Container Platform',
        normalizedId: 'openshift_container_platform',
        part: 'a',
        description: 'Enterprise Hybrid Cloud Kubernetes',
      },
      {
        name: 'JBoss Enterprise Application Platform',
        normalizedId: 'jboss_enterprise_application_platform',
        part: 'a',
        description: 'Jakarta EE Application Server',
      },
      {
        name: 'Ansible Automation Platform',
        normalizedId: 'ansible_automation_platform',
        part: 'a',
        description: 'Enterprise Infrastructure Automation',
      },
      {
        name: 'Satellite',
        normalizedId: 'satellite',
        part: 'a',
        description: 'Systems Lifecycle Management Solution',
      },
    ],
  },
  {
    name: 'Oracle',
    normalizedId: 'oracle',
    aliases: ['oracle_corp', 'oracle_corporation'],
    products: [
      {
        name: 'Database Server',
        normalizedId: 'database_server',
        part: 'a',
        description: 'Enterprise Relational Database Management',
      },
      {
        name: 'WebLogic Server',
        normalizedId: 'weblogic_server',
        part: 'a',
        description: 'Enterprise Java Application Server',
      },
      {
        name: 'Java SE Development Kit / JRE',
        normalizedId: 'jdk',
        part: 'a',
        description: 'Java Standard Edition Runtime Environment',
      },
      {
        name: 'MySQL Community & Enterprise',
        normalizedId: 'mysql',
        part: 'a',
        description: 'Open Source SQL Relational Database',
      },
      {
        name: 'VirtualBox',
        normalizedId: 'vm_virtualbox',
        part: 'a',
        description: 'Open Source Desktop Hypervisor',
      },
      {
        name: 'Solaris Operating System',
        normalizedId: 'solaris',
        part: 'o',
        description: 'Enterprise Unix Operating System',
      },
    ],
  },
  {
    name: 'Google',
    normalizedId: 'google',
    aliases: ['alphabet', 'google_llc'],
    products: [
      { name: 'Chrome Browser', normalizedId: 'chrome', part: 'a', description: 'Enterprise Web Browser' },
      {
        name: 'Android Operating System',
        normalizedId: 'android',
        part: 'o',
        description: 'Mobile & IoT Operating System',
      },
      {
        name: 'Kubernetes',
        normalizedId: 'kubernetes',
        part: 'a',
        description: 'Container Orchestration Platform',
      },
      { name: 'Go Runtime', normalizedId: 'go', part: 'a', description: 'Go Programming Language Runtime' },
    ],
  },
  {
    name: 'F5 Networks',
    normalizedId: 'f5',
    aliases: ['f5_networks', 'f5networks'],
    products: [
      {
        name: 'BIG-IP Local Traffic Manager (LTM)',
        normalizedId: 'big-ip_local_traffic_manager',
        part: 'a',
        description: 'Application Delivery Controller',
      },
      {
        name: 'BIG-IP Access Policy Manager (APM)',
        normalizedId: 'big-ip_access_policy_manager',
        part: 'a',
        description: 'Identity Federation & SSL-VPN',
      },
      {
        name: 'NGINX Plus / Open Source',
        normalizedId: 'nginx',
        part: 'a',
        description: 'High Performance Reverse Proxy and Load Balancer',
      },
      {
        name: 'BIG-IQ Centralized Management',
        normalizedId: 'big-iq',
        part: 'a',
        description: 'Security and Policy Orchestrator',
      },
    ],
  },
  {
    name: 'Citrix / Cloud Software Group',
    normalizedId: 'citrix',
    aliases: ['cloud_software_group', 'netscaler'],
    products: [
      {
        name: 'NetScaler ADC',
        normalizedId: 'netscaler_adc',
        part: 'a',
        description: 'Application Delivery Controller',
      },
      {
        name: 'NetScaler Gateway',
        normalizedId: 'netscaler_gateway',
        part: 'a',
        description: 'Secure Remote Access Gateway',
      },
      {
        name: 'Virtual Apps and Desktops',
        normalizedId: 'virtual_apps_and_desktops',
        part: 'a',
        description: 'VDI and Desktop Virtualization',
      },
      {
        name: 'Hypervisor (XenServer)',
        normalizedId: 'hypervisor',
        part: 'o',
        description: 'Enterprise Virtualization Platform',
      },
    ],
  },
  {
    name: 'Veeam Software',
    normalizedId: 'veeam',
    aliases: ['veeam_software', 'veeam_backup'],
    products: [
      {
        name: 'Backup & Replication',
        normalizedId: 'backup_and_replication',
        part: 'a',
        description: 'Enterprise Data Backup & Recovery Platform',
      },
      {
        name: 'Backup for Microsoft 365',
        normalizedId: 'backup_for_microsoft_365',
        part: 'a',
        description: 'SaaS Backup & Recovery for Microsoft 365',
      },
      {
        name: 'Backup for AWS',
        normalizedId: 'backup_for_aws',
        part: 'a',
        description: 'Cloud-Native Backup for AWS',
      },
      {
        name: 'Backup for Microsoft Azure',
        normalizedId: 'backup_for_azure',
        part: 'a',
        description: 'Cloud-Native Backup for Azure',
      },
      {
        name: 'Backup for Google Cloud',
        normalizedId: 'backup_for_google_cloud',
        part: 'a',
        description: 'Cloud-Native Backup for Google Cloud',
      },
      {
        name: 'Veeam ONE',
        normalizedId: 'veeam_one',
        part: 'a',
        description: 'Virtualization Management & Monitoring',
      },
      {
        name: 'Agent for Microsoft Windows',
        normalizedId: 'agent_for_windows',
        part: 'a',
        description: 'Endpoint Backup Agent for Windows',
      },
      {
        name: 'Agent for Linux',
        normalizedId: 'agent_for_linux',
        part: 'a',
        description: 'Endpoint Backup Agent for Linux',
      },
      {
        name: 'Backup for Salesforce',
        normalizedId: 'backup_for_salesforce',
        part: 'a',
        description: 'SaaS Backup & Recovery for Salesforce',
      },
      {
        name: 'Backup & Replication Community Edition',
        normalizedId: 'community_edition',
        part: 'a',
        description: 'Free Backup & Recovery for SMB',
      },
    ],
  },
  {
    name: 'Linux Foundation',
    normalizedId: 'linux',
    aliases: ['kernel.org', 'linux_foundation'],
    products: [
      {
        name: 'Linux Kernel',
        normalizedId: 'linux_kernel',
        part: 'o',
        description: 'Monolithic Unix-like Operating System Kernel',
      },
      {
        name: 'OpenSSL Cryptographic Toolkit',
        normalizedId: 'openssl',
        part: 'a',
        description: 'Transport Layer Security Library',
      },
      {
        name: 'systemd System Manager',
        normalizedId: 'systemd',
        part: 'a',
        description: 'Basic Building Block for Linux Systems',
      },
    ],
  },
  {
    name: 'HashiCorp',
    normalizedId: 'hashicorp',
    aliases: ['hashicorp_inc'],
    products: [
      {
        name: 'Vault Enterprise',
        normalizedId: 'vault',
        part: 'a',
        description: 'Secrets Management and Data Protection',
      },
      {
        name: 'Terraform Enterprise',
        normalizedId: 'terraform',
        part: 'a',
        description: 'Infrastructure as Code Platform',
      },
      {
        name: 'Consul Service Mesh',
        normalizedId: 'consul',
        part: 'a',
        description: 'Service Networking & Discovery Platform',
      },
      {
        name: 'Nomad Workload Orchestrator',
        normalizedId: 'nomad',
        part: 'a',
        description: 'Flexible Application Scheduler',
      },
    ],
  },
  {
    name: 'Canonical',
    normalizedId: 'canonical',
    aliases: ['ubuntu'],
    products: [
      {
        name: 'Ubuntu Linux LTS',
        normalizedId: 'ubuntu_linux',
        part: 'o',
        description: 'Debian-based Enterprise Server Linux',
      },
      {
        name: 'Snapd Service',
        normalizedId: 'snapd',
        part: 'a',
        description: 'Universal Package Management Daemon',
      },
      {
        name: 'MicroK8s',
        normalizedId: 'microk8s',
        part: 'a',
        description: 'Lightweight Zero-Ops Kubernetes',
      },
    ],
  },
  {
    name: 'SentinelOne',
    normalizedId: 'sentinelone',
    aliases: ['sentinelone_inc', 'sentinel_one'],
    products: [
      {
        name: 'Singularity Platform',
        normalizedId: 'singularity_platform',
        part: 'a',
        description: 'AI-powered Endpoint Protection and Response Platform',
      },
      {
        name: 'Singularity Complete',
        normalizedId: 'singularity_complete',
        part: 'a',
        description: 'Full-Stack Endpoint Detection and Response (EDR/XDR)',
      },
      {
        name: 'Singularity Cloud',
        normalizedId: 'singularity_cloud',
        part: 'a',
        description: 'Cloud Workload Protection and Container Security',
      },
      {
        name: 'Purple Knight',
        normalizedId: 'purple_knight',
        part: 'a',
        description: 'Active Directory and Azure Security Assessment',
      },
      {
        name: 'Vigilance',
        normalizedId: 'vigilance',
        part: 'a',
        description: 'Managed Detection and Response Service',
      },
    ],
  },
  {
    name: 'Adobe',
    normalizedId: 'adobe',
    aliases: ['adobe_systems'],
    products: [
      {
        name: 'Acrobat Reader DC',
        normalizedId: 'acrobat_reader',
        part: 'a',
        description: 'PDF Document Reader Client',
      },
      {
        name: 'Acrobat Pro DC',
        normalizedId: 'acrobat',
        part: 'a',
        description: 'PDF Authoring and Editing Application',
      },
      {
        name: 'Experience Manager (AEM)',
        normalizedId: 'experience_manager',
        part: 'a',
        description: 'Enterprise Content Management Platform',
      },
      {
        name: 'ColdFusion Application Server',
        normalizedId: 'coldfusion',
        part: 'a',
        description: 'Rapid Web Application Development',
      },
    ],
  },
];

/**
 * Searches and returns matching catalog vendors based on user input.
 */
export function searchCatalogVendors(query: string): CatalogVendor[] {
  if (!query || query.trim() === '') return ENTERPRISE_VENDOR_CATALOG;
  const q = query.toLowerCase().trim();
  return ENTERPRISE_VENDOR_CATALOG.filter(
    (v) =>
      v.name.toLowerCase().includes(q) ||
      v.normalizedId.toLowerCase().includes(q) ||
      v.aliases.some((a) => a.toLowerCase().includes(q)),
  );
}

/**
 * Returns available products for a given vendor name or alias.
 */
export function getCatalogProductsForVendor(vendorStr: string): CatalogProduct[] {
  if (!vendorStr || vendorStr.trim() === '') return [];
  const q = vendorStr.toLowerCase().trim();

  // Find exact or alias match
  const matchedVendor = ENTERPRISE_VENDOR_CATALOG.find(
    (v) => v.normalizedId === q || v.name.toLowerCase() === q || v.aliases.some((a) => a.toLowerCase() === q),
  );

  if (matchedVendor) {
    return matchedVendor.products;
  }

  // Partial match fallback
  const partial = ENTERPRISE_VENDOR_CATALOG.find(
    (v) => v.name.toLowerCase().includes(q) || v.normalizedId.includes(q),
  );

  return partial ? partial.products : [];
}

/**
 * Generates strict CPE 2.3 string from parameters.
 * Format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
 */
export function buildStrictCpe23(
  part: 'a' | 'o' | 'h',
  vendor: string,
  product: string,
  version: string = '*',
  targetHw: string = '*',
): string {
  // ':' and '\' break CPE 2.3 formatted-string tokenization and must be escaped
  // so inventory names such as "acme:gateway" still produce a parseable, matchable
  // criterion. The NVD dictionary additionally normalizes "+" and parentheses
  // (e.g. "notepad++" -> "notepad\+\+"), so those are escaped too so generated
  // CPEs align with published dictionary names. Wildcards stay unescaped.
  const escape = (value: string) =>
    value
      .replace(/\\/g, '\\\\')
      .replace(/:/g, '\\:')
      .replace(/\+/g, '\\+')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)');
  const normVendor = escape((vendor || 'any').toLowerCase().trim().replace(/\s+/g, '_'));
  const normProduct = escape((product || 'any').toLowerCase().trim().replace(/\s+/g, '_'));
  const normVersion = version?.trim() ? escape(version.trim()) : '*';
  const normHw = targetHw?.trim() ? escape(targetHw.trim()) : '*';

  return `cpe:2.3:${part}:${normVendor}:${normProduct}:${normVersion}:*:*:*:*:*:${normHw}:*`;
}
