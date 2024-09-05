
private rule isRTF
{
    strings:
        $magic_rtf = /^\s*{\\rt/
    condition:
        $magic_rtf and filesize &lt; 25MB
}

rule suspicious_RTF_1 : exploit CVE {
    meta:
        description = &quot;Rule to detect suspicious RTF files using known exploits (or) potentially dangerous commands&quot;
        author = &quot;Loginsoft Research Unit&quot;
        date = &quot;2020-05-25&quot;
        reference_1 = &quot;https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/fileformat/office_ms17_11882.rb%23L85&quot;
        reference_2 = &quot;https://github.com/embedi/CVE-2017-11882/tree/master/example&quot;
        hash = &quot;6fe87a14b97a5885a341e29e1b923e9c&quot;
        tested = &quot;https://www.hybrid-analysis.com/yara-search/results/a6212320f1e62190c235b6d953fb3a136f279cecc3ad468fde4c2c7b87140bec&quot;
        
    strings:
        $suspicious_1 = { 45 71 75 61 74 69 6F 6E 2E 33 } // check for &#039;Equation.3&#039;
        $suspicious_2 = { 30 61 30 31 30 38 35 61 35 61}  // check for &#039;font&#039; address where the overflow occurs i.e; 0a01085a5a
        $suspicious_3 = &quot;4d6963726f736f6674204571756174696f6e20332e30&quot; ascii  // check for &#039;Microsoft Equation&#039; 
        $suspicious_4 = { 50 61 63 6b 61 67 65 } //check for &#039;package&#039; keyword along with &#039;Equation.3 (this is gives false positives)&#039;
        $suspicious_5 = &quot;0002CE020000000000C000000000000046&quot; ascii nocase  //check for CLSID, commonly found in Metasploit exploit (ms_17_11882) 
        $suspicious_6 = &quot;objclass&quot; ascii nocase
    condition:
        isRTF and 
      4 of ($suspicious_*) and 
        ($suspicious_2 and $suspicious_5)
        
}

rule suspicious_RTF_2 : exploit CVE {
    meta:
        description = &quot;Rule to detect suspicious RTF files potentially dangerous commands/function&quot;
        author = &quot;Loginsoft Research Unit&quot;
        date = &quot;2020-05-25&quot;
        hash = &quot;d63a4d81fc43316490d68554bcfba373&quot;
        hash = &quot;65cb82f6853bf16f925942c7e00119d6&quot;
        hash = &quot;a0e6933f4e0497269620f44a083b2ed4&quot;
        tested = &quot;https://www.hybrid-analysis.com/yara-search/results/0af96a529de7c51d4ac526a1e454e3730566bdb6f3789dedec344d1b185c3e53&quot;
    strings:
      $suspicious_1 = &quot;objupdate&quot; nocase ascii                  // This forces the embedded object to update before it&#039;s displayed
      //$suspicious_2 = /4571\w+(e|E)2/                         // inefficient Regex detecting Equation header
      $suspicious_2 = /4571[a-zA-Z0-9]+(e|E)2[&quot;&quot;,(e|E)33]/      // check for Hex encoded form of &#039;Equation.3&#039; header
      $suspicious_3 = /(90){3,20}/ // check for Nop sledging
      $suspicious_4 = &quot;6d73687461&quot; nocase ascii  //check for mshta bin
    condition:
        isRTF and 
      	$suspicious_1 and (2 of ($suspicious*))
        
}

rule suspicious_RTF_withShellCode : exploit CVE {
    meta:
        author = &quot;Rich Warren&quot;
        description = &quot;Attempts to exploit CVE-2017-11882 using Packager&quot;
        reference = &quot;https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py&quot;
        tested = &quot;https://www.hybrid-analysis.com/yara-search/results/89b278531c28b674f23f46b2584c649801f27979be810c1754fdadf6c6081f88&quot;
        hash = &quot;65cb82f6853bf16f925942c7e00119d6&quot;
        hash = &quot;a0e6933f4e0497269620f44a083b2ed4&quot;
    strings:	
        
        $suspicious_1 = { 45 71 75 61 74 69 6F 6E 2E 33 }
        $suspicious_2 = { 50 61 63 6b 61 67 65 }
        $suspicious_3 = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase
        $suspicious_4 = &quot;objclass&quot; ascii nocase
        $suspicious_5 = &quot;6d73687461&quot; nocase ascii  //check for mshta binary
    condition:
        isRTF and $suspicious_3 and 2 of them 
}


 rule suspicious_RTF_usingURLMoniker : exploit CVE {
     meta:
        author = &quot;Loginsoft Research Unit&quot;
        description = &quot;Detecting malicious files which leverage URLMoniker with HTTP request&quot;
        reference = &quot;https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html&quot;
        reference = &quot;https://blog.nviso.eu/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/&quot;
        sample    = &quot;https://github.com/SyFi/cve-2017-0199&quot;
        date      = &quot;2020-06-01&quot;        
        tested   =  &quot;https://www.hybrid-analysis.com/yara-search/results/c55846e3f40e6ee6e87cfdb942653c738d299298e305b21ed4050d8d189faa81&quot;
    strings:
        
        $objdata = &quot;objdata 0105000002000000&quot; nocase
        $urlmoniker = &quot;E0C9EA79F9BACE118C8200AA004BA90B&quot; nocase
        $http = &quot;68007400740070003a002f002f00&quot; nocase
        $http1 = &quot;http&quot; nocase wide
    
    condition:
        isRTF and 
        ($objdata and $urlmoniker) or 
        ($urlmoniker and (1 of ($http*))) or 
        ($objdata and ( 1 of ($http*)))
 }

rule suspicious_RTF_CVE_2018_0802 : exploit CVE {
    meta:
        author = &quot;Rich Warren&quot;
        reference = &quot;https://github.com/rxwx/CVE-2018-0802/blob/master/yara/rtf_CVE_2018_0802.yara&quot;
        reference = &quot;https://research.checkpoint.com/2018/another-office-equation-rce-vulnerability/&quot;
        reference = &quot;https://www.fireeye.com/blog/threat-research/2019/06/government-in-central-asia-targeted-with-hawkball-backdoor.html&quot;
        tested = &quot;https://www.hybrid-analysis.com/yara-search/results/a18c08c8d54df2fd28e019308188dd620c4d6b45b76d87e81fc3bd101ccbb69c&quot;
    strings:
        $objupdate = &quot;objupdate&quot; nocase ascii         // This forces the embedded object to update before it&#039;s displayed
        $objdata = &quot;objdata 0105000002000000&quot; nocase // Loginsoft added this string since to produce efficient result. 
        $equation = { 45 71 75 61 74 69 6F 6E 2E 33 } 
        $header_and_shellcode = /03010[0-1]([0-9a-fA-F]){4}([0-9a-fA-F]+08)([0-9a-fA-F]{4})([0-9a-fA-F]{296})2500/ ascii nocase
    condition:
        uint32be(0) == 0x7B5C7274 and isRTF and all of them
 }

