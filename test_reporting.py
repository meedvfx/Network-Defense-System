import asyncio
import os
from datetime import datetime, timedelta

# Mock pour tester sans FastAPI
class MockSession:
    async def execute(self, query):
        class MockResult:
            def scalar_one(self):
                return 150 # fake total
            def __iter__(self):
                class Row:
                    def __init__(self, **kwargs):
                        self.__dict__.update(kwargs)
                yield Row(attack_type="DDoS", count=100, src_ip="192.168.1.100", country="France")
                yield Row(attack_type="PortScan", count=50, src_ip="10.0.0.1", country="US")
                yield Row(attack_type=None, count=80, src_ip="192.168.1.100", country="France")
                yield Row(attack_type=None, count=120, src_ip="172.16.0.5", country="Germany")

        return MockResult()

async def test_flow():
    from reporting.metrics_engine import get_period_metrics
    from reporting.trend_analysis import analyze_trends
    from reporting.threat_index import calculate_threat_index
    from reporting.prompt_builder import build_prompt_from_stats
    from reporting.llm_engine import generate_llm_analysis
    from reporting.report_formatter import generate_markdown_report
    from reporting.pdf_exporter import create_pdf_from_markdown

    session = MockSession()
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    print("1. Metrics:")
    metrics = await get_period_metrics(session, start_time, end_time)
    print(metrics)

    print("\n2. Trends:")
    trends = await analyze_trends(session, start_time, end_time)
    print(trends)

    print("\n3. Threat Index:")
    idx = calculate_threat_index(metrics, trends)
    print(idx)

    print("\n4. Prompt Builder:")
    prompt = build_prompt_from_stats(start_time, end_time, metrics, trends, idx)
    print(prompt[:200] + "...\n")

    # On ne fait pas l'appel LLM rée en test simple sauf si Ollama run.
    # llm = await generate_llm_analysis(prompt)
    llm = {
        "executive_summary": "Test OK",
        "technical_analysis": "DDoS dominant",
        "attacker_behavior": "Bots",
        "recommendations": ["Block IP"]
    }

    print("\n5. Markdown:")
    md = generate_markdown_report(start_time, end_time, metrics, trends, idx, llm)
    print(md[:300] + "...")

    print("\n6. PDF Exporter:")
    try:
        pdf_path = create_pdf_from_markdown(md)
        print(f"PDF generated at: {pdf_path}")
        print(f"File size: {os.path.getsize(pdf_path)} bytes")
    except Exception as e:
        print(f"PDF generation failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_flow())
