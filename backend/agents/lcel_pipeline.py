from langchain_core.prompts import ChatPromptTemplate"""

from langchain_core.output_parsers import StrOutputParserLCEL pipeline for streaming compliance explanations

from langchain_core.runnables import RunnableParallel, RunnablePassthrough"""

from langchain_openai import ChatOpenAIfrom langchain.schema import BaseMessage, HumanMessage, SystemMessage

from .tools.scanners import npm_audit_json, safety_check_json, bandit_scan_json, check_ssl_openssl, run_custom_security_checksfrom langchain.schema.output_parser import StrOutputParser

from .tools.normalize import summarize_npm_audit, summarize_safety, summarize_bandit, summarize_ssl, summarize_custom_checksfrom langchain_openai import ChatOpenAI

import asynciofrom langchain.schema.runnable import RunnablePassthrough, RunnableLambda

from typing import Dict, Any, AsyncGenerator

# Initialize LLMimport json

llm = ChatOpenAI(model="gpt-4", temperature=0, streaming=True)



# Prompts for different stages# System prompt for ISO 27001 compliance explanation

scan_explanation_prompt = ChatPromptTemplate.from_template("""COMPLIANCE_SYSTEM_PROMPT = """You are an expert ISO 27001 compliance analyst. Your role is to explain security scan results in the context of ISO 27001 controls and provide actionable insights for improving compliance posture.

You are an ISO 27001 security analyst providing real-time explanations during a security scan.

When analyzing scan results:

Current scan target: {host}1. Map findings to specific ISO 27001 controls

Scan phase: {phase}2. Explain the business impact and compliance implications

3. Provide clear, actionable remediation steps

Provide a clear, professional explanation of what's happening in this security assessment phase.4. Prioritize findings by risk and compliance impact

Keep it informative but accessible to both technical and management audiences.5. Use clear, professional language suitable for security officers



Focus on:Always structure your response with:

- What security controls are being evaluated- Executive Summary

- Why this scan phase is important for ISO 27001 compliance- Control-specific analysis

- What risks we're looking for- Risk assessment

- How this contributes to the overall security posture- Prioritized recommendations

- Implementation guidance

Current phase: {phase}

""")Be concise but thorough, focusing on practical compliance actions."""



findings_analysis_prompt = ChatPromptTemplate.from_template("""

You are an ISO 27001 compliance expert analyzing security scan results.def format_scan_context(scan_data: Dict[str, Any]) -> str:

    """Format scan data into context for the LLM"""

Scan summaries:    

{summaries}    host = scan_data.get("host", "unknown")

    summaries = scan_data.get("normalized_summaries", {})

Provide a detailed analysis of these security findings:    unified = scan_data.get("unified_summary", {})

    

1. **Risk Assessment**: Evaluate the business impact and likelihood of each finding    context_parts = [

2. **Control Mapping**: Map findings to specific ISO 27001:2022 controls        f"Target Host: {host}",

3. **Remediation Priority**: Suggest prioritization based on risk and compliance requirements        f"Overall Risk Level: {unified.get('risk_level', 'UNKNOWN')}",

4. **Management Recommendations**: Provide executive-level recommendations        f"Total Issues: {unified.get('total_issues', 0)}",

        f"High Severity Issues: {unified.get('high_severity_issues', 0)}",

Be specific about:        ""

- Which ISO 27001 controls are affected    ]

- Compliance gaps and their severity    

- Recommended remediation timeline    # Add scanner summaries

- Risk acceptance considerations for management    for scanner_name, summary in summaries.items():

""")        if summary.get("success"):

            context_parts.append(f"{scanner_name.upper()} Results:")

# Parallel scanning chain            context_parts.append(f"  - {summary.get('scan_summary', 'No summary available')}")

def create_parallel_scan_chain():            

    """Create a parallel scanning chain with real-time explanation"""            if "total_vulns" in summary:

                    context_parts.append(f"  - Vulnerabilities: {summary['total_vulns']}")

    async def run_npm_scan():            elif "total_issues" in summary:

        return {"npm": summarize_npm_audit(npm_audit_json())}                context_parts.append(f"  - Issues: {summary['total_issues']}")

                

    async def run_safety_scan():            recommendations = summary.get("recommendations", [])

        return {"safety": summarize_safety(safety_check_json())}            if recommendations:

                    context_parts.append(f"  - Key recommendations: {'; '.join(recommendations[:2])}")

    async def run_bandit_scan():            

        return {"bandit": summarize_bandit(bandit_scan_json("."))}            context_parts.append("")

        

    async def run_ssl_scan(host: str):    return "\n".join(context_parts)

        return {"ssl": summarize_ssl(check_ssl_openssl(host))}

    

    async def run_custom_scan():def create_compliance_chain():

        return {"custom": summarize_custom_checks(run_custom_security_checks())}    """Create the LCEL chain for compliance analysis"""

        

    parallel_scans = RunnableParallel({    # Initialize the LLM

        "npm": run_npm_scan,    llm = ChatOpenAI(

        "safety": run_safety_scan,         model="gpt-4",

        "bandit": run_bandit_scan,        temperature=0.1,

        "ssl": lambda inputs: run_ssl_scan(inputs["host"]),        streaming=True

        "custom": run_custom_scan    )

    })    

        # Create the chain

    return parallel_scans    chain = (

        {

# Main LCEL pipeline with streaming            "context": RunnableLambda(lambda x: format_scan_context(x)),

pipeline = (            "host": RunnableLambda(lambda x: x.get("host", "unknown"))

    RunnablePassthrough.assign(        }

        phase=lambda x: "Initializing security assessment..."        | RunnableLambda(lambda x: [

    )            SystemMessage(content=COMPLIANCE_SYSTEM_PROMPT),

    | RunnablePassthrough.assign(            HumanMessage(content=f"""Please analyze the following security scan results for {x['host']} and provide ISO 27001 compliance guidance:

        explanation=scan_explanation_prompt | llm | StrOutputParser()

    ){x['context']}

    | RunnablePassthrough.assign(

        phase=lambda x: "Running parallel security scans..."Focus on:

    )1. Mapping findings to ISO 27001 controls

    | RunnablePassthrough.assign(2. Assessing compliance gaps and risks

        explanation=scan_explanation_prompt | llm | StrOutputParser()3. Providing prioritized remediation recommendations

    )4. Explaining business impact of findings

    | RunnablePassthrough.assign(

        summaries=create_parallel_scan_chain()Provide a comprehensive but concise analysis suitable for security officers and compliance teams.""")

    )        ])

    | RunnablePassthrough.assign(        | llm

        phase=lambda x: "Analyzing findings and mapping to ISO 27001 controls..."        | StrOutputParser()

    )    )

    | RunnablePassthrough.assign(    

        analysis=findings_analysis_prompt | llm | StrOutputParser()    return chain

    )

    | RunnablePassthrough.assign(

        phase=lambda x: "Security assessment complete"def create_findings_explanation_chain():

    )    """Create chain for explaining specific findings"""

)    

    llm = ChatOpenAI(

# Streaming explanation pipeline for SSE        model="gpt-4",

explanation_pipeline = (        temperature=0.1,

    RunnablePassthrough.assign(        streaming=True

        phase=lambda x: "Starting comprehensive ISO 27001 security assessment"    )

    )    

    | scan_explanation_prompt     chain = (

    | llm         RunnableLambda(lambda x: [

    | StrOutputParser()            SystemMessage(content="""You are an ISO 27001 compliance expert. Explain security findings in detail, focusing on:

)1. The specific ISO 27001 control that applies
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