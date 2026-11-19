"""
The public API contract (see docs/API_STABILITY.md): what is importable, what is documented, what is typed,
and that importing the package is cheap and never reaches into a framework.
"""
import importlib, inspect, os, re, subprocess, sys
import pytest
import hb_eval_sdk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V2_LAYERS = ("policy_document", "topology", "lineage", "readiness_passport", "enrollment", "operational",
             "operational_passport", "enforcement", "enforcement_evidence", "assurance")


def test_version_is_a_clean_release_and_agrees_with_the_wire_protocol_rule():
    assert re.fullmatch(r"\d+\.\d+\.\d+", hb_eval_sdk.__version__), "a release must not carry a pre-release suffix"
    from hb_eval_sdk import config
    assert config.PROTOCOL_VERSION != config.MEASUREMENT_PROTOCOL_VERSION


def test_every_public_submodule_imports_and_is_reachable_as_an_attribute():
    for name in hb_eval_sdk.PUBLIC_SUBMODULES:
        assert getattr(hb_eval_sdk, name).__name__ == f"hb_eval_sdk.{name}"
        assert name in dir(hb_eval_sdk)


@pytest.mark.parametrize("layer", V2_LAYERS)
def test_each_v2_layer_declares_its_public_surface_and_every_name_in_it_is_real_and_documented(layer):
    module = importlib.import_module(f"hb_eval_sdk.{layer}")
    assert hasattr(module, "__all__"), f"{layer} must declare __all__: that list IS its public API"
    undocumented = []
    for name in module.__all__:
        obj = getattr(module, name)                                   # raises if __all__ lies
        if (inspect.isclass(obj) or inspect.isfunction(obj)) and not inspect.getdoc(obj):
            undocumented.append(name)
    assert not undocumented, f"public names without a docstring in {layer}: {undocumented}"


def test_names_exported_by_more_than_one_layer_stay_in_their_own_namespace():
    """`Decision` exists in both enforcement and enforcement_contract. Flattening either into the top-level
    package would let one silently shadow the other, which is why the layers are submodules."""
    from hb_eval_sdk import enforcement, enforcement_contract
    assert enforcement.Decision is not enforcement_contract.Decision
    assert not hasattr(hb_eval_sdk, "Decision")


def test_lazy_integration_names_resolve_and_unknown_names_fail_clearly():
    from hb_eval_sdk import adapt_langchain_agent, HBEvalCallback, HBEvalLangChainCallback, adapt_langgraph_agent, adapt_crewai_agent
    assert HBEvalCallback is HBEvalLangChainCallback and callable(adapt_langchain_agent) and callable(adapt_langgraph_agent) and callable(adapt_crewai_agent)
    with pytest.raises(AttributeError, match="has no attribute 'definitely_not_here'"):
        hb_eval_sdk.definitely_not_here
    assert {"adapt_langchain_agent", "enrollment"} <= set(dir(hb_eval_sdk))


def test_the_package_ships_type_information():
    assert os.path.exists(os.path.join(os.path.dirname(hb_eval_sdk.__file__), "py.typed"))


def test_importing_the_package_never_imports_an_optional_framework():
    """Importing the core SDK must not pay for, or be broken by, LangChain, LangGraph, CrewAI, MCP or
    OpenTelemetry. Run in a subprocess so earlier tests cannot have loaded them already."""
    code = ("import sys, hb_eval_sdk\n"
            "heavy = [m for m in ('langchain_core', 'langgraph', 'crewai', 'mcp', 'opentelemetry') if m in sys.modules]\n"
            "print('LOADED:' + ','.join(heavy))")
    env = dict(os.environ, PYTHONPATH=ROOT)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stderr[-500:]
    assert r.stdout.strip() == "LOADED:", f"import hb_eval_sdk pulled in: {r.stdout.strip()}"
