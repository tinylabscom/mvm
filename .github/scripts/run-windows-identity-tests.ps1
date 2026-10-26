Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) {
    throw 'This runtime witness requires Windows.'
}
if (-not $env:RUNNER_TEMP) {
    throw 'RUNNER_TEMP must identify the isolated CI scratch directory.'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$logs = Join-Path $env:RUNNER_TEMP 'mvm-windows-identity'
New-Item -ItemType Directory -Path $logs -ErrorAction Stop | Out-Null
$env:CARGO_BUILD_JOBS = '2'
$env:CARGO_TARGET_DIR = Join-Path $env:RUNNER_TEMP 'mvm-windows-identity-target'
$env:CARGO_HOME = Join-Path $env:RUNNER_TEMP 'mvm-windows-identity-cargo'
$env:MVM_HOME = Join-Path $env:RUNNER_TEMP 'mvm-windows-identity-home'
$env:RUST_TEST_THREADS = '1'

$commands = [System.Collections.Generic.List[object]]::new()
$results = [System.Collections.Generic.List[object]]::new()
$receipt = [ordered]@{
    head = $env:GITHUB_SHA
    runner_os = $env:RUNNER_OS
    os = [Environment]::OSVersion.VersionString
    filesystem = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)).DriveFormat
    powershell = $PSVersionTable.PSVersion.ToString()
    toolchain = '1.97.1'
    compiler_qualification = 'Existing CI stable pin, not the repository nightly compiler.'
    target = 'x86_64-pc-windows-msvc'
    unsupported = @('Unix raw-filename observations', 'POSIX mode and symlink identity cases')
    commands = $commands
    tests = $results
    complete = $false
}

function Invoke-Logged {
    param([string] $Program, [string[]] $Arguments, [string] $Log)
    $record = [ordered]@{ program = $Program; arguments = $Arguments; log = $Log; exit = $null }
    $commands.Add($record)
    $output = @(& $Program @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $logs $Log))
    $record.exit = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed; see $Log"
    }
    return @($output | ForEach-Object { "$_" })
}

function Control-Hashes {
    $hashes = [ordered]@{}
    foreach ($path in @(
        'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
        '.github/workflows/ci.yml', '.github/scripts/run-windows-identity-tests.ps1',
        'crates/mvm-build/Cargo.toml',
        'crates/mvm-build/src/image_source/tests/git_identity.rs',
        'crates/mvm-build/src/image_source/tests/repository.rs',
        'crates/mvm-build/src/image_source/emitter.rs',
        'crates/mvm-build/tests/local_producer_pair.rs',
        'crates/mvm-build/tests/fixtures/local-producer-v2.json',
        'crates/mvm-build/tests/fixtures/local-producer-manifests.json',
        'crates/mvm-core/src/image_set/tests/local.rs',
        'crates/mvm-core/src/registry_pack_store.rs'
    )) {
        $hashes[$path] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    }
    return $hashes
}

function Compile-Test {
    param([string] $Package, [string[]] $Selection, [string] $TargetName, [string] $Label)
    $arguments = @('+1.97.1', 'test', '--locked', '-p', $Package)
    if ($Package -eq 'mvm-build') {
        $arguments += '--no-default-features'
    }
    $features = 'test-support'
    if ($Package -eq 'mvm-core') {
        # The registry_pack_store witness lives behind the off-by-default
        # host-state feature; this lane exists to run host-only modules on
        # Windows, so it enables the feature explicitly.
        $features = 'test-support,host-state'
    }
    $arguments += @('--features', $features) + $Selection
    $arguments += @('--no-run', '--message-format=json')
    $output = Invoke-Logged 'cargo' $arguments "$Label-compile.log"
    $executables = @(
        foreach ($line in $output) {
            if (-not $line.StartsWith('{')) { continue }
            $event = $line | ConvertFrom-Json
            if ($event.reason -eq 'compiler-artifact' -and $event.target.name -eq $TargetName -and
                $event.profile.test -and $event.executable) {
                $event.executable
            }
        }
    )
    if ($executables.Count -ne 1 -or -not (Test-Path -LiteralPath $executables[0] -PathType Leaf) -or
        [IO.Path]::GetExtension($executables[0]) -ne '.exe') {
        throw "Expected exactly one Windows test executable for $Label."
    }
    return $executables[0]
}

function Test-Inventory {
    param(
        [string] $Executable, [string] $Label, [string[]] $Expected, [string] $Prefix,
        [string[]] $Required = @()
    )
    $listed = @(Invoke-Logged $Executable @('--list', '--format', 'terse') "$Label-list.log")
    $ignored = @(Invoke-Logged $Executable @('--list', '--ignored', '--format', 'terse') "$Label-ignored.log")
    $names = @($listed | Where-Object { $_ -match '^(.+): test$' } |
        ForEach-Object { $_.Substring(0, $_.Length - 6) })
    $ignoredNames = @($ignored | Where-Object { $_ -match '^(.+): test$' } |
        ForEach-Object { $_.Substring(0, $_.Length - 6) })
    if ($Expected.Count -eq 0 -or $names.Count -eq 0 -or
        @($names | Sort-Object -Unique).Count -ne $names.Count -or
        @($Expected | Sort-Object -Unique).Count -ne $Expected.Count) {
        throw "Empty or duplicate inventory for $Label."
    }
    $selected = @($names | Where-Object { $_.StartsWith($Prefix, [StringComparison]::Ordinal) })
    if (@(Compare-Object ($Expected | Sort-Object) ($selected | Sort-Object) -CaseSensitive).Count -ne 0) {
        throw "The exact supported test inventory changed for $Label."
    }
    if ($Required.Count -eq 0) {
        $Required = $Expected
    }
    if (@($Required | Sort-Object -Unique).Count -ne $Required.Count) {
        throw "Duplicate required test for $Label."
    }
    foreach ($name in $Required) {
        if ($Expected -cnotcontains $name) {
            throw "Required test is absent from the expected inventory: $name"
        }
        if ($ignoredNames -ccontains $name) {
            throw "Required test is ignored: $name"
        }
        $number = $results.Count + 1
        $output = @(Invoke-Logged $Executable @($name, '--exact', '--test-threads=1', '--nocapture') "test-$number.log")
        if (@($output | Where-Object { $_ -match '^test result: ok\. 1 passed; 0 failed; 0 ignored;' }).Count -ne 1) {
            throw "Expected exactly one unignored runtime pass for $name."
        }
        $results.Add([ordered]@{ name = $name; executable = $Executable; log = "test-$number.log"; passed = 1 })
    }
}

$gitTests = @(
    'boolean_settings_are_validated_even_for_clean_repositories',
    'system_policy_defaults_and_explicit_override_precedence',
    'proven_windows_attributes_opt_in_is_separate_from_system_config',
    'neutral_python_reference_vectors_exercise_rust_encoder',
    'staged_bytes_are_distinct_even_when_working_bytes_return_to_head',
    'index_stat_cache_does_not_change_the_identity',
    'index_performance_flags_do_not_hide_working_edits',
    'conflict_stages_are_preserved',
    'ignores_include_nested_negations_and_administrative_files_never_contribute',
    'active_external_transforms_are_refused_without_execution',
    'built_in_text_and_ident_normalization_is_in_process',
    'linked_worktree_uses_its_own_head_and_index',
    'uninitialized_gitlink_differs_from_malformed_initialized_submodule',
    'unsafe_paths_are_refused',
    'sparse_directories_expand_in_process_without_hiding_present_edits',
    'initialized_submodule_dirty_bytes_are_recursive_inputs_and_cycles_are_bounded',
    'observation_needs_no_executables_and_ignores_repository_redirects',
    'split_indexes_hydrate_shared_entries_replacements_and_deletions',
    'native_config_keeps_context_and_level_precedence_without_mutating_files',
    'unsupported_config_includes_fail_closed_in_root_and_contributing_sources',
    'deleted_cached_home_never_overrides_current_declared_rule_paths',
    'nonexistent_optional_home_and_xdg_config_are_absent_not_native_fallbacks',
    'relative_rule_resources_are_worktree_rooted_from_outside_cwd',
    'nested_fixture_index_uses_git_separators',
    'prefix_rule_resources_are_expanded_without_include_prefix_semantics'
) | ForEach-Object { "image_source::git::tests::$_" }

$emitterTests = @(
    'supplied_roots_require_exact_bytes_and_mode_without_source_fallback',
    'malformed_root_and_mixed_contracts_refuse_and_cleanup',
    'partial_sets_alone_use_source_compatibility',
    'a_partial_set_from_a_checkout_without_a_declaration_records_none',
    'copied_bytes_are_inspected_and_original_changes_do_not_change_the_set',
    'post_inspection_staged_mutation_refuses_and_cleans_up',
    'changed_identity_refuses_and_cleans_up'
) | ForEach-Object { "image_source::build::emitter::tests::$_" }
$requiredEmitterTests = @(
    'image_source::build::emitter::tests::changed_identity_refuses_and_cleans_up',
    'image_source::build::emitter::tests::post_inspection_staged_mutation_refuses_and_cleans_up'
)

$pairTests = @(
    'neutral_reference_refuses_tampering_before_interpreting_data',
    'raw_name_reference_requires_complete_supported_shape',
    'shared_portable_repository_observation_matrix',
    'in_process_producer_and_strict_consumer_preserve_schema3_contract',
    'repository::image_source_fixture_preserves_commit_bytes_without_ambient_git'
)
$requiredPairTests = @(
    'shared_portable_repository_observation_matrix',
    'neutral_reference_refuses_tampering_before_interpreting_data',
    'raw_name_reference_requires_complete_supported_shape',
    'in_process_producer_and_strict_consumer_preserve_schema3_contract'
)
$coreTests = @('image_set::tests::local::wire::a_worktree_state_is_tagged_and_closed')
$applicationTests = @(
    'registry_pack_store::tests::open_application_descriptor_preserves_unsupported_safe_reader_refusal'
)

try {
    $receipt.controls_before = Control-Hashes
    $rust = @(Invoke-Logged 'rustc' @('+1.97.1', '-Vv') 'rustc.log')
    if (@($rust | Where-Object { $_ -ceq 'host: x86_64-pc-windows-msvc' }).Count -ne 1) {
        throw 'Expected the native Windows MSVC toolchain.'
    }
    $receipt.rustc = $rust
    $receipt.cargo = @(Invoke-Logged 'cargo' @('+1.97.1', '-V') 'cargo.log')
    $build = Compile-Test 'mvm-build' @('--lib') 'mvm_build' 'build'
    $pair = Compile-Test 'mvm-build' @('--test', 'local_producer_pair') 'local_producer_pair' 'pair'
    $core = Compile-Test 'mvm-core' @('--lib') 'mvm_core' 'core'
    Test-Inventory $build 'git-identity' $gitTests 'image_source::git::tests::'
    Test-Inventory $build 'emitter' $emitterTests 'image_source::build::emitter::tests::' $requiredEmitterTests
    Test-Inventory $pair 'pair' $pairTests '' $requiredPairTests
    Test-Inventory $core 'core-v1-refusal' $coreTests $coreTests[0]
    Test-Inventory $core 'application-local-reader-refusal' $applicationTests $applicationTests[0]
    if ($gitTests.Count -ne 25 -or $requiredEmitterTests.Count -ne 2 -or
        $requiredPairTests.Count -ne 4 -or $applicationTests.Count -ne 1 -or
        $results.Count -ne 33) {
        throw 'The required runtime witness count changed.'
    }
    $receipt.complete = $true
} finally {
    $receipt.controls_after = Control-Hashes
    if (($receipt.controls_before | ConvertTo-Json -Compress) -cne
        ($receipt.controls_after | ConvertTo-Json -Compress)) {
        $receipt.complete = $false
        $receipt | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 (Join-Path $logs 'receipt.json')
        throw 'A source, fixture, manifest or lock changed during the runtime witness.'
    }
    $receipt | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 (Join-Path $logs 'receipt.json')
}
