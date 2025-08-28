$cf = 'D:\Program Files\LLVM\bin\clang-format.exe'
Get-ChildItem -Path . -Recurse -File |
  Where-Object { $_.Extension -in '.c', '.h' } |
  Where-Object { $_.FullName -notmatch '\\3rd\\' } |
  ForEach-Object { & $cf -i --style=file --fallback-style=LLVM $_.FullName }