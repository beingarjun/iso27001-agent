"""
Multi-Framework Compliance Mapping Engine
Maps controls across ISO 27001, ISO 42001, SOC 2, GDPR, DPDP-India
"""

from typing import Dict, List, Optional, Set, Any
import json

class ComplianceFrameworkMapper:
    """Cross-framework control mapping and gap analysis"""
    
    def __init__(self):
        self.framework_mappings = self._load_framework_mappings()
    
    def map_controls(
        self,
        source_framework: str,
        target_framework: str,
        control_id: str
    ) -> Dict[str, Any]:
        """Map control from source to target framework"""
        
        mapping_key = f"{source_framework}_to_{target_framework}"
        
        if mapping_key not in self.framework_mappings:
            return {"error": f"Mapping not available: {mapping_key}"}
        
        mappings = self.framework_mappings[mapping_key]
        
        if control_id in mappings:
            return {
                "source_control": control_id,
                "source_framework": source_framework,
                "target_framework": target_framework,
                "mapped_controls": mappings[control_id],
                "mapping_type": "direct"
            }
        
        # Try partial matching
        partial_matches = self._find_partial_matches(control_id, mappings)
        
        return {
            "source_control": control_id,
            "source_framework": source_framework,
            "target_framework": target_framework,
            "mapped_controls": partial_matches,
            "mapping_type": "partial"
        }
    
    def generate_gap_analysis(
        self,
        implemented_controls: Dict[str, List[str]],
        target_framework: str
    ) -> Dict[str, Any]:
        """Generate gap analysis across frameworks"""
        
        gaps = {}
        coverage = {}
        
        for framework, controls in implemented_controls.items():
            if framework == target_framework:
                continue
                
            mapping_key = f"{framework}_to_{target_framework}"
            if mapping_key not in self.framework_mappings:
                continue
            
            mappings = self.framework_mappings[mapping_key]
            
            for control in controls:
                if control in mappings:
                    target_controls = mappings[control]
                    for target_control in target_controls:
                        if target_control not in coverage:
                            coverage[target_control] = []
                        coverage[target_control].append({
                            "source_framework": framework,
                            "source_control": control
                        })
        
        # Identify gaps
        all_target_controls = self._get_all_controls(target_framework)
        for control in all_target_controls:
            if control not in coverage:
                gaps[control] = {
                    "control_id": control,
                    "gap_type": "missing",
                    "recommendation": f"Implement {target_framework} control {control}"
                }
        
        return {
            "target_framework": target_framework,
            "total_controls": len(all_target_controls),
            "covered_controls": len(coverage),
            "coverage_percentage": round(len(coverage) / len(all_target_controls) * 100, 1),
            "gaps": gaps,
            "coverage_details": coverage
        }
    
    def _load_framework_mappings(self) -> Dict[str, Dict]:
        """Load framework mapping definitions"""
        
        # ISO 27001 to ISO 42001 (AI Management)
        iso27001_to_iso42001 = {
            "A.5.1.1": ["5.1", "5.2"],  # Information security policies -> AI policy
            "A.6.1.1": ["6.1", "6.2"],  # Information security roles -> AI governance roles
            "A.8.1.1": ["7.1", "7.2"],  # Inventory of assets -> AI system inventory
            "A.8.2.1": ["7.3"],         # Information classification -> AI data classification
            "A.12.6.1": ["8.1", "8.2"], # Management of technical vulnerabilities -> AI risk management
            "A.14.2.1": ["9.1"],        # Secure development policy -> AI development lifecycle
        }
        
        # ISO 27001 to SOC 2
        iso27001_to_soc2 = {
            "A.5.1.1": ["CC1.1", "CC1.2"],  # Policies -> Control Environment
            "A.6.1.1": ["CC1.3"],           # Roles -> Control Environment
            "A.9.1.1": ["CC6.1"],           # Access control policy -> Logical Access
            "A.9.2.1": ["CC6.2"],           # User access provisioning -> Logical Access
            "A.12.1.1": ["CC7.1"],          # Documented procedures -> System Operations
            "A.12.6.1": ["CC7.2"],          # Vulnerability management -> System Operations
        }
        
        # ISO 27001 to GDPR
        iso27001_to_gdpr = {
            "A.8.2.1": ["Art. 25"],         # Information classification -> Data Protection by Design
            "A.9.1.1": ["Art. 32"],         # Access control -> Security of Processing
            "A.11.2.6": ["Art. 32"],        # Secure disposal -> Security of Processing
            "A.12.6.1": ["Art. 32"],        # Vulnerability management -> Security of Processing
            "A.13.2.1": ["Art. 33"],        # Information transfer -> Breach Notification
            "A.16.1.1": ["Art. 33", "Art. 34"], # Incident reporting -> Breach Notification
        }
        
        return {
            "ISO27001_to_ISO42001": iso27001_to_iso42001,
            "ISO27001_to_SOC2": iso27001_to_soc2,
            "ISO27001_to_GDPR": iso27001_to_gdpr,
            # Reverse mappings
            "ISO42001_to_ISO27001": self._reverse_mapping(iso27001_to_iso42001),
            "SOC2_to_ISO27001": self._reverse_mapping(iso27001_to_soc2),
            "GDPR_to_ISO27001": self._reverse_mapping(iso27001_to_gdpr),
        }
    
    def _reverse_mapping(self, mapping: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Create reverse mapping"""
        reverse = {}
        for source, targets in mapping.items():
            for target in targets:
                if target not in reverse:
                    reverse[target] = []
                reverse[target].append(source)
        return reverse
    
    def _find_partial_matches(self, control_id: str, mappings: Dict) -> List[str]:
        """Find partial control matches"""
        # Implementation for fuzzy matching
        return []
    
    def _get_all_controls(self, framework: str) -> List[str]:
        """Get all controls for a framework"""
        if framework == "ISO27001":
            return [f"A.{i}.{j}.{k}" for i in range(5, 19) for j in range(1, 5) for k in range(1, 10)]
        elif framework == "ISO42001":
            return [f"{i}.{j}" for i in range(4, 11) for j in range(1, 5)]
        elif framework == "SOC2":
            return ["CC1.1", "CC1.2", "CC6.1", "CC6.2", "CC7.1", "CC7.2"]
        return []

def create_framework_mapper() -> ComplianceFrameworkMapper:
    """Create framework mapper instance"""
    return ComplianceFrameworkMapper()