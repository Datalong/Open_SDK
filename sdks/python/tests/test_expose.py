import asyncio
from a2net import expose

def test_expose_decorator_attributes():
    @expose("ws://127.0.0.1:18999", name="Calculator", description="算力节点", tags=["math"])
    def calc(x: str) -> str:
        """文档注释"""
        return f"result: {x}"

    assert calc.address.startswith("did:key:")
    assert calc.agent_name == "Calculator"
    assert calc.agent_description == "算力节点"
    assert "math" in calc.agent_tags
    assert callable(calc.serve)
