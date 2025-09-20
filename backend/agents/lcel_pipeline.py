"""
LCEL pipeline for streaming compliance explanations
"""
from langchain.schema import BaseMessage, HumanMessage, SystemMessage
from langchain.schema.output_parser import StrOutputParser
from langchain_openai import ChatOpenAI
from langchain.schema.runnable import RunnablePassthrough, RunnableLambda
from typing import Dict, Any, AsyncGenerator
import json


# System prompt for ISO 27001 compliance explanation
COMPLIANCE_SYSTEM_PROMPT = """You are an expert ISO 27001 compliance analyst. Your role is to explain security scan results in the context of ISO 27001 controls and provide actionable insights for improving compliance posture.

When analyzing scan results:
1. Map findings to specific ISO 27001 controls
2. Explain the business impact and compliance implications
3. Provide clear, actionable remediation steps
4. Prioritize findings by risk and compliance impact
5. Use clear, professional language suitable for security officers

Always structure your response with:
- Executive Summary
- Control-specific analysis
- Risk assessment
- Prioritized recommendations
- Implementation guidance

Be concise but thorough, focusing on practical compliance actions."""


def format_scan_context(scan_data: Dict[str, Any]) -> str:
    """Format scan data into context for the LLM"""
    
    host = scan_data.get("host", "unknown")
    summaries = scan_data.get("normalized_summaries", {})
    unified = scan_data.get("unified_summary", {})
    
    context_parts = [
        f"Target Host: {host}",
        f"Overall Risk Level: {unified.get('risk_level', 'UNKNOWN')}",
        f"Total Issues: {unified.get('total_issues', 0)}",
        f"High Severity Issues: {unified.get('high_severity_issues', 0)}",
        ""
    ]
    
    # Add scanner summaries
    for scanner_name, summary in summaries.items():
        if summary.get("success"):
            context_parts.append(f"{scanner_name.upper()} Results:")
            context_parts.append(f"  - {summary.get('scan_summary', 'No summary available')}")
            
            if "total_vulns" in summary:
                context_parts.append(f"  - Vulnerabilities: {summary['total_vulns']}")
            elif "total_issues" in summary:
                context_parts.append(f"  - Issues: {summary['total_issues']}")
            
            recommendations = summary.get("recommendations", [])
            if recommendations:
                context_parts.append(f"  - Key recommendations: {'; '.join(recommendations[:2])}")
            
            context_parts.append("")
    
    return "\n".join(context_parts)


def create_compliance_chain():
    """Create the LCEL chain for compliance analysis"""
    
    # Initialize the LLM
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.1,
        streaming=True
    )
    
    # Create the chain
    chain = (
        {
            "context": RunnableLambda(lambda x: format_scan_context(x)),
            "host": RunnableLambda(lambda x: x.get("host", "unknown"))
        }
        | RunnableLambda(lambda x: [
            SystemMessage(content=COMPLIANCE_SYSTEM_PROMPT),
            HumanMessage(content=f"""Please analyze the following security scan results for {x['host']} and provide ISO 27001 compliance guidance:

{x['context']}

Focus on:
1. Mapping findings to ISO 27001 controls
2. Assessing compliance gaps and risks
3. Providing prioritized remediation recommendations
4. Explaining business impact of findings

Provide a comprehensive but concise analysis suitable for security officers and compliance teams.""")
        ])
        | llm
        | StrOutputParser()
    )
    
    return chain


def create_findings_explanation_chain():
    """Create chain for explaining specific findings"""
    
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.1,
        streaming=True
    )
    
    chain = (
        RunnableLambda(lambda x: [
            SystemMessage(content="""You are an ISO 27001 compliance expert. Explain security findings in detail, focusing on:
1. The specific ISO 27001 control that applies
2. Why this finding represents a compliance gap
3. The potential business impact
4. Step-by-step remediation guidance
5. How to prevent similar issues

Be practical and actionable in your advice."""),
            HumanMessage(content=f"""Explain this security finding in detail:

Control: {x.get('control', 'Unknown')}
Severity: {x.get('severity', 'Unknown')}
Title: {x.get('title', 'Unknown')}
Description: {x.get('detail', 'No description')}
Evidence: {x.get('evidence', 'No evidence')}

Provide a thorough explanation suitable for security teams.""")
        ])
        | llm
        | StrOutputParser()
    )
    
    return chain


def create_remediation_chain():
    """Create chain for detailed remediation guidance"""
    
    llm = ChatOpenAI(
        model="gpt-4", 
        temperature=0.1,
        streaming=True
    )
    
    chain = (
        RunnableLambda(lambda x: [
            SystemMessage(content="""You are a cybersecurity implementation expert specializing in ISO 27001 compliance. Provide detailed, step-by-step remediation instructions that include:

1. Immediate actions to take
2. Long-term preventive measures  
3. Testing and validation steps
4. Documentation requirements for compliance
5. Monitoring and maintenance procedures

Make instructions specific, actionable, and suitable for technical teams."""),
            HumanMessage(content=f"""Provide detailed remediation steps for this finding:

Control: {x.get('control', 'Unknown')}
Finding: {x.get('title', 'Unknown')}
Current Issue: {x.get('detail', 'No description')}
Evidence: {x.get('evidence', 'No evidence')}

Include technical steps, compliance considerations, and ongoing monitoring recommendations.""")
        ])
        | llm
        | StrOutputParser()
    )
    
    return chain


# Create the main pipeline instances
compliance_pipeline = create_compliance_chain()
findings_pipeline = create_findings_explanation_chain()
remediation_pipeline = create_remediation_chain()


async def stream_compliance_analysis(scan_data: Dict[str, Any]) -> AsyncGenerator[str, None]:
    """Stream compliance analysis of scan results"""
    
    async for chunk in compliance_pipeline.astream(scan_data):
        if chunk:
            yield chunk


async def stream_finding_explanation(finding_data: Dict[str, Any]) -> AsyncGenerator[str, None]:
    """Stream detailed explanation of a specific finding"""
    
    async for chunk in findings_pipeline.astream(finding_data):
        if chunk:
            yield chunk


async def stream_remediation_guidance(finding_data: Dict[str, Any]) -> AsyncGenerator[str, None]:
    """Stream detailed remediation guidance"""
    
    async for chunk in remediation_pipeline.astream(finding_data):
        if chunk:
            yield chunk