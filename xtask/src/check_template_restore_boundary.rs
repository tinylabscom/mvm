//! Enforce the two workload-dispatch authority classes in production source.
//!
//! Fresh authority belongs to typed launch owners and named lower
//! runtime/backend implementations. Same identity has exactly two owners:
//! authenticated vm_full checkpoint restore and sealed instance resume. A
//! cold-tier durable-session resume is a fresh boot under a newly admitted plan.

use anyhow::{Result, bail};
use std::collections::HashSet;
use std::path::Path;
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, FnArg, ImplItem, Item, Meta, Pat, Stmt, Token,
    TraitItem, Type, UseTree, Visibility,
};

use crate::rust_source::{blank_comments_and_strings, blank_ranges, strip_cfg_test_items};

const CRATES_ROOT: &str = "crates";
const CLI_VM_FULL_OWNER: &str = "crates/mvm-cli/src/commands/vm/checkpoint.rs";
const CLIENT_VM_FULL_OWNER: &str = "crates/mvm-client/src/checkpoint.rs";
const RUNTIME_CHECKPOINT: &str = "crates/mvm-runtime/src/checkpoint/mod.rs";
const SEALED_RESUME_OWNER: &str = "crates/mvm-runtime/src/vm/instance_snapshot.rs";
const CLIENT_SEALED_RESUME_FILES: [&str; 2] = [
    "crates/mvm-client/src/local.rs",
    "crates/mvm-client/src/local/resume.rs",
];
const CLIENT_BOOT: &str = "crates/mvm-client/src/boot.rs";
const CLIENT_CHECKPOINT: &str = "crates/mvm-client/src/checkpoint.rs";
const CLIENT_FULL_FORK: &str = "crates/mvm-client/src/checkpoint/vm_full.rs";
const HOSTD_FULL_FORK: &str = "crates/mvm-hostd/src/plan_admission/retained_vm_full.rs";
const RESTORE_CHECKPOINT_OWNERS: [&str; 2] = [
    "crates/mvm-core/src/mailbox/journal/checkpoint.rs",
    "crates/mvm-core/src/mailbox/journal/recovery.rs",
];

const RAW_TEMPLATE_IDENTIFIERS: [&str; 5] = [
    "restore_from_template_snapshot",
    "FlakeRunConfig",
    "template_snapshot_dir",
    "slot_snapshot_dir",
    "allocate_slot",
];
const GENERIC_CLIENT_STARTS: [&str; 3] = [
    "start_prepared",
    "start_prepared_custodied",
    "start_prepared_custodied_with_verified_runtime",
];
const FRESH_DISPATCH_OWNERS: [(&str, &[&str]); 7] = [
    (
        "start_custodied_verified_release",
        &[
            "crates/mvm-cli/src/exec/transient.rs",
            "crates/mvm-hostd/src/plan_admission/start.rs",
            "crates/mvm-runtime/src/apple_container_backend.rs",
            "crates/mvm-runtime/src/backend.rs",
            "crates/mvm-runtime/src/workload_runner/runner/backend.rs",
        ],
    ),
    (
        "claim_standby_owned_via_runner",
        &[
            "crates/mvm-hostd/src/plan_admission/start.rs",
            "crates/mvm-runtime/src/backend.rs",
        ],
    ),
    (
        "claim_standby_via_runner",
        &["crates/mvm-runtime/src/backend.rs"],
    ),
    (
        "start_custodied",
        &[
            "crates/mvm-runtime/src/backend.rs",
            "crates/mvm-runtime/src/workload_runner/runner/backend.rs",
        ],
    ),
    (
        "fork_vm_full_verified_with_rollback",
        &[
            "crates/mvm-hostd/src/plan_admission/restore.rs",
            HOSTD_FULL_FORK,
            RUNTIME_CHECKPOINT,
        ],
    ),
    ("dispatch_firecracker", &[CLIENT_FULL_FORK, HOSTD_FULL_FORK]),
    ("dispatch_hvf", &[CLIENT_FULL_FORK, HOSTD_FULL_FORK]),
];
const BACKEND_START_OWNERS: &[&str] = &[
    "crates/mvm-hostd/src/plan_admission/start.rs",
    "crates/mvm-runtime/src/actor_teardown/native.rs",
    "crates/mvm-runtime/src/backend.rs",
];
const UNTYPED_FULL_RESTORER: [&str; 2] = ["ForkRestore", "ForkRestorer"];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let mut files = Vec::new();
    crate::fs_walk::for_each_file(
        &workspace.join(CRATES_ROOT),
        Some("rs"),
        &mut |path, source| {
            let rel = relative(workspace, path);
            if !is_test_path(&rel) {
                files.push((rel, source.to_string(), production_code(source)));
            }
        },
    )?;

    let mut violations = Vec::new();
    for (rel, original, production) in &files {
        check_raw_template(rel, production, &mut violations);
        check_generic_client_start(rel, production, &mut violations);
        check_fresh_dispatch_ownership(rel, production, &mut violations);
        check_backend_start_ownership(rel, original, &mut violations);
        check_same_identity_ownership(rel, production, &mut violations);
        check_full_fork_boundary(rel, production, &mut violations);
    }
    require_owner_seams(&files, &mut violations);

    if !violations.is_empty() {
        bail!(
            "workload dispatch authority boundary is violated:\n  {}",
            violations.join("\n  ")
        );
    }
    Ok(())
}

fn check_raw_template(rel: &str, source: &str, violations: &mut Vec<String>) {
    for identifier in RAW_TEMPLATE_IDENTIFIERS {
        let restricted = identifier == "restore_from_template_snapshot"
            || rel.starts_with("crates/mvm-cli/src/")
            || rel.starts_with("crates/mvm-client/src/");
        if restricted {
            collect_identifier(rel, source, identifier, violations);
        }
    }
}

fn check_generic_client_start(rel: &str, source: &str, violations: &mut Vec<String>) {
    if !rel.starts_with("crates/mvm-client/src/") {
        return;
    }
    for identifier in GENERIC_CLIENT_STARTS {
        collect_identifier(rel, source, identifier, violations);
    }
}

fn check_fresh_dispatch_ownership(rel: &str, source: &str, violations: &mut Vec<String>) {
    for (identifier, owners) in FRESH_DISPATCH_OWNERS {
        if !owners.contains(&rel) {
            collect_identifier(rel, source, identifier, violations);
        }
    }
}

fn check_backend_start_ownership(rel: &str, source: &str, violations: &mut Vec<String>) {
    if !rel.contains("/src/") {
        return;
    }
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => {
            violations.push(format!(
                "{rel}: production Rust parse failed closed: {error}"
            ));
            return;
        }
    };
    let mut aliases = BackendAliasCollector::default();
    aliases.visit_file(&file);
    aliases.resolve();
    let mut visitor = BackendStartVisitor {
        rel,
        violations,
        backend_type_aliases: aliases.aliases,
        backend_bindings: vec![HashSet::new()],
        raw_fork_aliases: vec![HashSet::new()],
    };
    visitor.visit_file(&file);
}

struct BackendStartVisitor<'a> {
    rel: &'a str,
    violations: &'a mut Vec<String>,
    backend_type_aliases: HashSet<String>,
    backend_bindings: Vec<HashSet<String>>,
    raw_fork_aliases: Vec<HashSet<String>>,
}

#[derive(Default)]
struct BackendAliasCollector {
    aliases: HashSet<String>,
    candidates: Vec<(String, String)>,
}

impl BackendAliasCollector {
    fn resolve(&mut self) {
        self.aliases.insert("AnyBackend".to_string());
        loop {
            let before = self.aliases.len();
            for (alias, target) in &self.candidates {
                if self.aliases.contains(target) {
                    self.aliases.insert(alias.clone());
                }
            }
            if self.aliases.len() == before {
                break;
            }
        }
    }
}

impl<'ast> Visit<'ast> for BackendAliasCollector {
    fn visit_item(&mut self, item: &'ast Item) {
        if item_is_test_only(item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let Some(target) = type_last_ident(&item.ty) {
            self.candidates
                .push((item.ident.to_string(), target.to_string()));
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut aliases = Vec::new();
        collect_named_use(&item.tree, "AnyBackend", &mut aliases);
        self.aliases.extend(aliases);
    }
}

impl<'ast> Visit<'ast> for BackendStartVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if item_is_test_only(item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if impl_item_attrs(item).is_some_and(attrs_are_test_only) {
            return;
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if trait_item_attrs(item).is_some_and(attrs_are_test_only) {
            return;
        }
        syn::visit::visit_trait_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.visit_function(&item.sig.inputs, &item.block);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.visit_function(&item.sig.inputs, &item.block);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(block) = &item.default {
            self.visit_function(&item.sig.inputs, block);
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.push_scope();
        for statement in &block.stmts {
            self.visit_stmt(statement);
        }
        self.pop_scope();
    }

    fn visit_stmt(&mut self, statement: &'ast Stmt) {
        if let Stmt::Local(local) = statement {
            if attrs_are_test_only(&local.attrs) {
                return;
            }
            if let Some(init) = &local.init {
                self.visit_expr(&init.expr);
                if let Some((_, diverge)) = &init.diverge {
                    self.visit_expr(diverge);
                }
            }
            if pat_type(&local.pat).is_some_and(|ty| self.is_backend_type(ty))
                || local
                    .init
                    .as_ref()
                    .is_some_and(|init| self.is_backend_value(&init.expr))
            {
                let mut names = Vec::new();
                collect_pat_names(&local.pat, &mut names);
                self.backend_bindings
                    .last_mut()
                    .expect("backend visitor always has a scope")
                    .extend(names);
            }
            return;
        }
        syn::visit::visit_stmt(self, statement);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut aliases = Vec::new();
        collect_named_use(&item.tree, "fork_vm_full", &mut aliases);
        self.raw_fork_aliases
            .last_mut()
            .expect("backend visitor always has a scope")
            .extend(aliases);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "start"
            && self.is_backend_value(&call.receiver)
            && !backend_start_allowed(self.rel, call)
        {
            self.violations.push(format!(
                "{}: backend `start` is outside its exact lower owner allowlist",
                self.rel
            ));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if self.is_any_backend_start_call(call) && !BACKEND_START_OWNERS.contains(&self.rel) {
            self.violations.push(format!(
                "{}: `AnyBackend::start` is outside its exact lower owner allowlist",
                self.rel
            ));
        }
        if self.is_raw_fork_call(call) && self.rel != RUNTIME_CHECKPOINT {
            self.violations.push(format!(
                "{}: raw `fork_vm_full` is outside its lower runtime owner",
                self.rel
            ));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

impl BackendStartVisitor<'_> {
    fn visit_function<'ast>(
        &mut self,
        inputs: &'ast Punctuated<FnArg, Token![,]>,
        block: &'ast syn::Block,
    ) {
        self.push_scope();
        for input in inputs {
            if let FnArg::Typed(input) = input
                && self.is_backend_type(&input.ty)
            {
                let mut names = Vec::new();
                collect_pat_names(&input.pat, &mut names);
                self.backend_bindings
                    .last_mut()
                    .expect("backend visitor always has a scope")
                    .extend(names);
            }
        }
        for statement in &block.stmts {
            self.visit_stmt(statement);
        }
        self.pop_scope();
    }

    fn push_scope(&mut self) {
        self.backend_bindings.push(HashSet::new());
        self.raw_fork_aliases.push(HashSet::new());
    }

    fn pop_scope(&mut self) {
        self.backend_bindings.pop();
        self.raw_fork_aliases.pop();
    }

    fn is_backend_type(&self, ty: &Type) -> bool {
        type_last_ident(ty)
            .is_some_and(|ident| self.backend_type_aliases.contains(&ident.to_string()))
    }

    fn is_backend_value(&self, expression: &Expr) -> bool {
        match expression {
            Expr::Path(path) => path.path.get_ident().is_some_and(|ident| {
                self.backend_bindings
                    .iter()
                    .rev()
                    .any(|scope| scope.contains(&ident.to_string()))
            }),
            Expr::Call(call) => {
                let Expr::Path(function) = call.func.as_ref() else {
                    return false;
                };
                let mut segments = function.path.segments.iter().rev();
                matches!(
                    (segments.next(), segments.next()),
                    (Some(_), Some(owner))
                        if self.backend_type_aliases.contains(&owner.ident.to_string())
                )
            }
            Expr::Group(group) => self.is_backend_value(&group.expr),
            Expr::Paren(paren) => self.is_backend_value(&paren.expr),
            Expr::Reference(reference) => self.is_backend_value(&reference.expr),
            Expr::Try(expression) => self.is_backend_value(&expression.expr),
            _ => false,
        }
    }

    fn is_any_backend_start_call(&self, call: &ExprCall) -> bool {
        let Expr::Path(function) = call.func.as_ref() else {
            return false;
        };
        if function
            .path
            .segments
            .last()
            .is_some_and(|method| method.ident == "start")
            && function
                .qself
                .as_ref()
                .is_some_and(|qself| self.is_backend_type(&qself.ty))
        {
            return true;
        }
        let mut segments = function.path.segments.iter().rev();
        matches!(
            (segments.next(), segments.next()),
            (Some(method), Some(owner))
                if method.ident == "start"
                    && self.backend_type_aliases.contains(&owner.ident.to_string())
        )
    }

    fn is_raw_fork_call(&self, call: &ExprCall) -> bool {
        let Expr::Path(function) = call.func.as_ref() else {
            return false;
        };
        function.path.segments.last().is_some_and(|segment| {
            segment.ident == "fork_vm_full"
                || self
                    .raw_fork_aliases
                    .iter()
                    .rev()
                    .any(|scope| scope.contains(&segment.ident.to_string()))
        })
    }
}

fn backend_start_allowed(rel: &str, call: &ExprMethodCall) -> bool {
    if BACKEND_START_OWNERS.contains(&rel) {
        return true;
    }
    if rel != "crates/mvm-cli/src/exec/transient.rs" || call.args.len() != 1 {
        return false;
    }
    let Expr::Field(receiver) = call.receiver.as_ref() else {
        return false;
    };
    let Expr::Path(base) = receiver.base.as_ref() else {
        return false;
    };
    let Some(argument) = call.args.first() else {
        return false;
    };
    let Expr::Field(argument) = argument else {
        return false;
    };
    let Expr::Path(argument_base) = argument.base.as_ref() else {
        return false;
    };
    matches!(&receiver.member, syn::Member::Named(name) if name == "backend")
        && base.path.is_ident("attempt")
        && matches!(&argument.member, syn::Member::Named(name) if name == "start_config")
        && argument_base.path.is_ident("attempt")
}

fn type_last_ident(ty: &Type) -> Option<&syn::Ident> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        Type::Group(group) => type_last_ident(&group.elem),
        Type::Paren(paren) => type_last_ident(&paren.elem),
        Type::Reference(reference) => type_last_ident(&reference.elem),
        _ => None,
    }
}

fn pat_type(pat: &Pat) -> Option<&Type> {
    let Pat::Type(pat) = pat else {
        return None;
    };
    Some(&pat.ty)
}

fn collect_pat_names(pat: &Pat, names: &mut Vec<String>) {
    match pat {
        Pat::Ident(pat) => names.push(pat.ident.to_string()),
        Pat::Reference(pat) => collect_pat_names(&pat.pat, names),
        Pat::Type(pat) => collect_pat_names(&pat.pat, names),
        Pat::Tuple(pat) => {
            for item in &pat.elems {
                collect_pat_names(item, names);
            }
        }
        Pat::TupleStruct(pat) => {
            for item in &pat.elems {
                collect_pat_names(item, names);
            }
        }
        Pat::Struct(pat) => {
            for field in &pat.fields {
                collect_pat_names(&field.pat, names);
            }
        }
        Pat::Slice(pat) => {
            for item in &pat.elems {
                collect_pat_names(item, names);
            }
        }
        Pat::Or(pat) => {
            for case in &pat.cases {
                collect_pat_names(case, names);
            }
        }
        Pat::Paren(pat) => collect_pat_names(&pat.pat, names),
        _ => {}
    }
}

fn collect_named_use(tree: &UseTree, target: &str, aliases: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => collect_named_use(&path.tree, target, aliases),
        UseTree::Name(name) if name.ident == target => aliases.push(name.ident.to_string()),
        UseTree::Rename(rename) if rename.ident == target => {
            aliases.push(rename.rename.to_string())
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_named_use(item, target, aliases);
            }
        }
        _ => {}
    }
}

fn check_same_identity_ownership(rel: &str, source: &str, violations: &mut Vec<String>) {
    if has_identifier(source, "restore_checkpoint") && !RESTORE_CHECKPOINT_OWNERS.contains(&rel) {
        violations.push(format!(
            "{rel}: `restore_checkpoint` creates a third same-identity checkpoint owner"
        ));
    }
    if has_identifier(source, "restore_same_identity_checkpoint")
        && rel != CLIENT_VM_FULL_OWNER
        && rel != RUNTIME_CHECKPOINT
    {
        violations.push(format!(
            "{rel}: typed same-identity restore primitive is exposed outside its client owner"
        ));
    }

    for identifier in ["verify_and_resume", "verify_and_resume_from_dir"] {
        if has_identifier(source, identifier)
            && rel != SEALED_RESUME_OWNER
            && !CLIENT_SEALED_RESUME_FILES.contains(&rel)
        {
            violations.push(format!(
                "{rel}: `{identifier}` creates a third sealed-resume owner"
            ));
        }
    }

    if has_identifier(source, "guarded_load_resume")
        && rel != SEALED_RESUME_OWNER
        && rel != "crates/mvm-vmm/src/snapshot.rs"
        && rel != "crates/mvm-vmm/src/fc/snapshot.rs"
    {
        violations.push(format!(
            "{rel}: `guarded_load_resume` is outside the sealed owner or named lower implementation"
        ));
    }
}

fn check_full_fork_boundary(rel: &str, source: &str, violations: &mut Vec<String>) {
    if (rel.starts_with("crates/mvm-cli/src/") || rel.starts_with("crates/mvm-client/src/"))
        && rel != CLIENT_FULL_FORK
    {
        for identifier in UNTYPED_FULL_RESTORER {
            collect_identifier(rel, source, identifier, violations);
        }
        collect_identifier(rel, source, "VmFullForkRestorer", violations);
    }

    if rel == CLIENT_FULL_FORK {
        for forbidden in ["ForkRestore", "ForkRestorer"] {
            if has_identifier(source, forbidden) {
                violations.push(format!(
                    "{rel}: untyped full-VM restorer callback `{forbidden}`"
                ));
            }
        }
        if source.contains("|child") {
            violations.push(format!("{rel}: untyped full-VM restorer callback `|child`"));
        }
        for required in ["dispatch_firecracker", "dispatch_hvf"] {
            if !has_identifier(source, required) {
                violations.push(format!("{rel}: typed full-VM dispatch lost `{required}`"));
            }
        }
    }

    if rel == HOSTD_FULL_FORK {
        for required in [
            "Firecracker(&'a mvm_runtime::firecracker::FcForkRestorer)",
            "Hvf(&'a mvm_runtime::hvf_restore::HvfForkRestorer)",
        ] {
            if !source.contains(required) {
                violations.push(format!(
                    "{rel}: typed full-VM restorer boundary lost `{required}`"
                ));
            }
        }
    }
}

fn require_owner_seams(files: &[(String, String, String)], violations: &mut Vec<String>) {
    require_identifier(
        files,
        CLI_VM_FULL_OWNER,
        "restore_vm_full_checkpoint",
        violations,
    );
    require_identifier(
        files,
        CLIENT_VM_FULL_OWNER,
        "restore_same_identity_checkpoint",
        violations,
    );
    if let Some((_, _, source)) = files.iter().find(|(rel, _, _)| rel == RUNTIME_CHECKPOINT)
        && (!source.contains("let target_vm = meta.vm_name.clone()")
            || !source.contains("let restore = vm_full_restorer_for(&meta)"))
    {
        violations.push(format!(
            "{RUNTIME_CHECKPOINT}: same-identity target and restorer must derive from one authenticated metadata value"
        ));
    }
    require_identifier(
        files,
        SEALED_RESUME_OWNER,
        "verify_and_resume_from_dir",
        violations,
    );
    require_identifier(
        files,
        SEALED_RESUME_OWNER,
        "guarded_load_resume",
        violations,
    );

    if let Some((_, _, source)) = files.iter().find(|(rel, _, _)| rel == CLIENT_BOOT)
        && !has_identifier(source, "start_prepared_owned")
    {
        violations.push(format!(
            "{CLIENT_BOOT}: crate-private native-owned handoff `start_prepared_owned` is missing"
        ));
    }

    if let Some((_, original, _)) = files.iter().find(|(rel, _, _)| rel == CLIENT_CHECKPOINT) {
        let identifiers = match public_use_identifiers(original) {
            Ok(identifiers) => identifiers,
            Err(error) => {
                violations.push(format!(
                    "{CLIENT_CHECKPOINT}: public-use parse failed closed: {error}"
                ));
                Vec::new()
            }
        };
        for forbidden in [
            "RestoreParams",
            "RestoredChild",
            "fork_vm_full",
            "restore_checkpoint",
            "restore_same_identity_checkpoint",
            "vm_full_restorer_for",
            "FcForkRestorer",
            "HvfForkRestorer",
        ] {
            if identifiers.iter().any(|identifier| identifier == forbidden) {
                violations.push(format!(
                    "{CLIENT_CHECKPOINT}: public checkpoint facade reexports `{forbidden}`"
                ));
            }
        }
        if identifiers.iter().any(|identifier| identifier == "*") {
            violations.push(format!(
                "{CLIENT_CHECKPOINT}: public checkpoint facade uses a glob reexport"
            ));
        }
    }
}

fn public_use_identifiers(source: &str) -> Result<Vec<String>, syn::Error> {
    let file = syn::parse_file(source)?;
    let mut identifiers = Vec::new();
    collect_public_uses(&file.items, &mut identifiers);
    Ok(identifiers)
}

fn collect_public_uses(items: &[Item], identifiers: &mut Vec<String>) {
    for item in items {
        if item_is_test_only(item) {
            continue;
        }
        match item {
            Item::Use(item) if matches!(item.vis, Visibility::Public(_)) => {
                collect_use_tree(&item.tree, identifiers);
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_public_uses(items, identifiers);
                }
            }
            _ => {}
        }
    }
}

fn collect_use_tree(tree: &UseTree, identifiers: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            identifiers.push(path.ident.to_string());
            collect_use_tree(&path.tree, identifiers);
        }
        UseTree::Name(name) => identifiers.push(name.ident.to_string()),
        UseTree::Rename(rename) => {
            identifiers.push(rename.ident.to_string());
            identifiers.push(rename.rename.to_string());
        }
        UseTree::Glob(_) => identifiers.push("*".to_string()),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, identifiers);
            }
        }
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn item_is_test_only(item: &Item) -> bool {
    attrs_are_test_only(item_attrs(item))
}

fn impl_item_attrs(item: &ImplItem) -> Option<&[Attribute]> {
    match item {
        ImplItem::Const(item) => Some(&item.attrs),
        ImplItem::Fn(item) => Some(&item.attrs),
        ImplItem::Type(item) => Some(&item.attrs),
        ImplItem::Macro(item) => Some(&item.attrs),
        _ => None,
    }
}

fn trait_item_attrs(item: &TraitItem) -> Option<&[Attribute]> {
    match item {
        TraitItem::Const(item) => Some(&item.attrs),
        TraitItem::Fn(item) => Some(&item.attrs),
        TraitItem::Type(item) => Some(&item.attrs),
        TraitItem::Macro(item) => Some(&item.attrs),
        _ => None,
    }
}

#[derive(Clone)]
enum CfgExpr {
    Test,
    Atom(String),
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
}

fn attrs_are_test_only(attrs: &[Attribute]) -> bool {
    if attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("test"))
    {
        return true;
    }
    let expressions: Vec<_> = attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .filter_map(|attribute| attribute.parse_args::<Meta>().ok())
        .map(cfg_expr)
        .collect();
    !expressions.is_empty() && cfg_implies_test(&CfgExpr::All(expressions))
}

fn cfg_expr(meta: Meta) -> CfgExpr {
    match meta {
        Meta::Path(path) if path.is_ident("test") => CfgExpr::Test,
        Meta::Path(path) => CfgExpr::Atom(path_to_string(&path)),
        Meta::NameValue(value) => CfgExpr::Atom(format!(
            "{}={}",
            path_to_string(&value.path),
            cfg_value(&value.value)
        )),
        Meta::List(list) if list.path.is_ident("all") => CfgExpr::All(
            parse_cfg_arguments(&list)
                .unwrap_or_else(|| vec![CfgExpr::Atom(format!("all({})", list.tokens))]),
        ),
        Meta::List(list) if list.path.is_ident("any") => CfgExpr::Any(
            parse_cfg_arguments(&list)
                .unwrap_or_else(|| vec![CfgExpr::Atom(format!("any({})", list.tokens))]),
        ),
        Meta::List(list) if list.path.is_ident("not") => {
            let mut arguments = parse_cfg_arguments(&list).unwrap_or_default();
            if arguments.len() == 1 {
                CfgExpr::Not(Box::new(arguments.remove(0)))
            } else {
                CfgExpr::Atom(format!("not({})", list.tokens))
            }
        }
        Meta::List(list) => {
            CfgExpr::Atom(format!("{}({})", path_to_string(&list.path), list.tokens))
        }
    }
}

fn parse_cfg_arguments(list: &syn::MetaList) -> Option<Vec<CfgExpr>> {
    list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .ok()
        .map(|items| items.into_iter().map(cfg_expr).collect())
}

fn cfg_implies_test(expression: &CfgExpr) -> bool {
    let mut atoms = HashSet::new();
    collect_cfg_atoms(expression, &mut atoms);
    if atoms.len() > 12 {
        return false;
    }
    let atoms: Vec<_> = atoms.into_iter().collect();
    for bits in 0..(1usize << atoms.len()) {
        if eval_cfg(expression, false, &atoms, bits) {
            return false;
        }
    }
    true
}

fn collect_cfg_atoms(expression: &CfgExpr, atoms: &mut HashSet<String>) {
    match expression {
        CfgExpr::Test => {}
        CfgExpr::Atom(atom) => {
            atoms.insert(atom.clone());
        }
        CfgExpr::All(items) | CfgExpr::Any(items) => {
            for item in items {
                collect_cfg_atoms(item, atoms);
            }
        }
        CfgExpr::Not(item) => collect_cfg_atoms(item, atoms),
    }
}

fn eval_cfg(expression: &CfgExpr, test: bool, atoms: &[String], bits: usize) -> bool {
    match expression {
        CfgExpr::Test => test,
        CfgExpr::Atom(atom) => atoms
            .iter()
            .position(|candidate| candidate == atom)
            .is_some_and(|index| bits & (1 << index) != 0),
        CfgExpr::All(items) => items.iter().all(|item| eval_cfg(item, test, atoms, bits)),
        CfgExpr::Any(items) => items.iter().any(|item| eval_cfg(item, test, atoms, bits)),
        CfgExpr::Not(item) => !eval_cfg(item, test, atoms, bits),
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn cfg_value(expression: &Expr) -> String {
    let Expr::Lit(expression) = expression else {
        return "<unknown>".to_string();
    };
    match &expression.lit {
        syn::Lit::Str(value) => format!("{:?}", value.value()),
        syn::Lit::ByteStr(value) => format!("{:?}", value.value()),
        syn::Lit::CStr(value) => format!("{:?}", value.value()),
        syn::Lit::Byte(value) => value.value().to_string(),
        syn::Lit::Char(value) => format!("{:?}", value.value()),
        syn::Lit::Int(value) => value.base10_digits().to_string(),
        syn::Lit::Float(value) => value.base10_digits().to_string(),
        syn::Lit::Bool(value) => value.value.to_string(),
        syn::Lit::Verbatim(value) => value.to_string(),
        _ => "<unknown>".to_string(),
    }
}

fn require_identifier(
    files: &[(String, String, String)],
    rel: &str,
    identifier: &str,
    violations: &mut Vec<String>,
) {
    match files.iter().find(|(path, _, _)| path == rel) {
        Some((_, _, source)) if has_identifier(source, identifier) => {}
        Some(_) => violations.push(format!(
            "{rel}: required owner seam `{identifier}` is missing"
        )),
        None => violations.push(format!("{rel}: required owner module is missing")),
    }
}

fn production_code(source: &str) -> String {
    let blanked = blank_comments_and_strings(source);
    let test_only_ranges = logical_test_only_item_ranges(source, &blanked);
    strip_cfg_test_items(&blank_ranges(&blanked, &test_only_ranges))
}

fn logical_test_only_item_ranges(source: &str, blanked: &str) -> Vec<std::ops::Range<usize>> {
    let source_chars: Vec<_> = source.chars().collect();
    let blanked_chars: Vec<_> = blanked.chars().collect();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index + 5 <= blanked_chars.len() {
        if blanked_chars.get(index..index + 5) != Some(&['#', '[', 'c', 'f', 'g']) {
            index += 1;
            continue;
        }
        let mut cursor = index + 5;
        let mut parentheses = 0usize;
        let mut end = None;
        while cursor < blanked_chars.len() {
            match blanked_chars[cursor] {
                '(' => parentheses += 1,
                ')' => parentheses = parentheses.saturating_sub(1),
                ']' if parentheses == 0 => {
                    end = Some(cursor + 1);
                    break;
                }
                _ => {}
            }
            cursor += 1;
        }
        let Some(attribute_end) = end else {
            break;
        };
        let attribute: String = source_chars[index..attribute_end].iter().collect();
        let probe = format!("{attribute}\nfn __mvm_cfg_probe() {{}}");
        if syn::parse_file(&probe)
            .ok()
            .and_then(|file| file.items.into_iter().next())
            .is_some_and(|item| item_is_test_only(&item))
        {
            ranges.push(index..cfg_item_end(&blanked_chars, attribute_end));
        }
        index = attribute_end;
    }
    ranges
}

fn cfg_item_end(chars: &[char], from: usize) -> usize {
    let mut braces = 0usize;
    let mut groups = 0usize;
    let mut index = from;
    while index < chars.len() {
        match chars[index] {
            '(' | '[' => groups += 1,
            ')' | ']' => groups = groups.saturating_sub(1),
            '{' if groups == 0 => braces += 1,
            '}' if groups == 0 => {
                braces = braces.saturating_sub(1);
                if braces == 0 {
                    return index + 1;
                }
            }
            ';' if groups == 0 && braces == 0 => return index + 1,
            _ => {}
        }
        index += 1;
    }
    chars.len()
}

fn relative(workspace: &Path, path: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("/test.rs")
        || rel.ends_with("/tests.rs")
}

fn collect_identifier(rel: &str, source: &str, identifier: &str, violations: &mut Vec<String>) {
    for (index, line) in source.lines().enumerate() {
        if has_identifier(line, identifier) {
            violations.push(format!("{rel}:{}: `{identifier}`", index + 1));
        }
    }
}

fn has_identifier(source: &str, identifier: &str) -> bool {
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .any(|token| token == identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_tree_has_exact_dispatch_owners() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("current production dispatch owners stay classified");
    }

    #[test]
    fn direct_public_client_and_cli_dispatch_escape_hatches_are_rejected() {
        for (path, source, needle) in [
            (
                "crates/mvm-client/src/lib.rs",
                "pub fn start_prepared() {}\n",
                "start_prepared",
            ),
            (
                "crates/mvm-cli/src/direct.rs",
                "fn boot(backend: Backend) { backend.start_custodied_verified_release(); }\n",
                "start_custodied_verified_release",
            ),
            (
                "crates/mvm-cli/src/claim.rs",
                "fn claim(backend: Backend) { backend.claim_standby_via_runner(); }\n",
                "claim_standby_via_runner",
            ),
        ] {
            let tree = fixture();
            write(&tree, path, source);
            let error = run(&tree).expect_err("direct dispatch must fail");
            assert!(error.to_string().contains(needle), "{error:#}");
            remove(tree);
        }
    }

    #[test]
    fn fresh_dispatch_is_rejected_in_unrelated_client_and_hostd_modules() {
        for (path, source, needle) in [
            (
                "crates/mvm-client/src/unrelated.rs",
                "fn bypass(bound: Bound) { bound.dispatch_hvf(); }\n",
                "dispatch_hvf",
            ),
            (
                "crates/mvm-hostd/src/unrelated.rs",
                "fn bypass(backend: Backend) { backend.start_custodied_verified_release(); }\n",
                "start_custodied_verified_release",
            ),
            (
                "crates/mvm-client/src/direct_start.rs",
                "fn bypass(backend: AnyBackend, config: Config) { backend.start(&config); }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-client/src/direct_custodied.rs",
                "fn bypass(backend: AnyBackend, config: Config) { \
                 backend.start_custodied(&config, Vec::new()); }\n",
                "start_custodied",
            ),
            (
                "crates/mvm-hostd/src/direct_fork.rs",
                "fn bypass() { fork_vm_full(); }\n",
                "fork_vm_full",
            ),
            (
                "crates/mvm-client/src/associated_start.rs",
                "fn bypass(backend: AnyBackend, config: Config) { \
                 AnyBackend::start(&backend, &config); }\n",
                "AnyBackend::start",
            ),
        ] {
            let tree = fixture();
            write(&tree, path, source);
            let error = run(&tree).expect_err("fresh dispatch needs an exact owner");
            assert!(error.to_string().contains(needle), "{error:#}");
            remove(tree);
        }
    }

    #[test]
    fn any_backend_dispatch_is_rejected_independent_of_receiver_spelling() {
        for (path, source, needle) in [
            (
                "crates/mvm-unrelated/src/lib.rs",
                "fn bypass(engine: AnyBackend, config: Config) { engine.start(&config); }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-unrelated/src/impl_param.rs",
                "impl Owner { fn bypass(&self, engine: &AnyBackend, config: Config) { \
                 engine.start(&config); } }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-unrelated/src/inferred.rs",
                "fn bypass(config: Config) -> Result<()> { \
                 let engine = (&(AnyBackend::for_started_vm(\"vm\")?)); \
                 engine.start(&config)?; Ok(()) }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-unrelated/src/constructed.rs",
                "fn bypass(config: Config) -> Result<()> { \
                 AnyBackend::for_started_vm(\"vm\")?.start(&config)?; Ok(()) }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-unrelated/src/alias.rs",
                "type SelectedBackend = AnyBackend;\n\
                 fn bypass(engine: SelectedBackend, config: Config) { \
                 SelectedBackend::start(&engine, &config); }\n",
                "AnyBackend::start",
            ),
            (
                "crates/mvm-unrelated/src/use_alias.rs",
                "use mvm_runtime::AnyBackend as Engine;\n\
                 fn bypass(engine: Engine, config: Config) { engine.start(&config); }\n",
                "backend `start`",
            ),
            (
                "crates/mvm-unrelated/src/qself.rs",
                "fn bypass(engine: AnyBackend, config: Config) { \
                 <AnyBackend>::start(&engine, &config); }\n",
                "AnyBackend::start",
            ),
            (
                "crates/mvm-unrelated/src/raw_fork_alias.rs",
                "fn bypass() { use mvm_runtime::checkpoint::fork_vm_full as raw_fork; \
                 raw_fork(); }\n",
                "fork_vm_full",
            ),
            (
                "crates/mvm-hostd/src/actor_lifecycle/activation.rs",
                "fn production_activation(engine: AnyBackend, config: Config) { \
                 engine.start(&config); }\n",
                "backend `start`",
            ),
        ] {
            let tree = fixture();
            write(&tree, path, source);
            let error = run(&tree).expect_err("unclassified AnyBackend dispatch must fail");
            assert!(error.to_string().contains(needle), "{path}: {error:#}");
            remove(tree);
        }
    }

    #[test]
    fn only_cfgs_that_imply_test_are_excluded() {
        for cfg in ["not(test)", "any(test, unix)", "mvm_unknown_predicate"] {
            let tree = fixture();
            write(
                &tree,
                "crates/mvm-unrelated/src/cfg.rs",
                &format!(
                    "#[cfg({cfg})]\n\
                     fn bypass(engine: AnyBackend, config: Config) {{ engine.start(&config); }}\n"
                ),
            );
            let error = run(&tree).expect_err("production-capable cfg must remain scanned");
            assert!(error.to_string().contains("backend `start`"), "{error:#}");
            remove(tree);
        }

        for cfg in ["test", "all(test, unix)", "any(test, all(test, unix))"] {
            let tree = fixture();
            write(
                &tree,
                "crates/mvm-unrelated/src/cfg.rs",
                &format!(
                    "#[cfg({cfg})]\n\
                     fn bypass(engine: AnyBackend, config: Config) {{ engine.start(&config); }}\n"
                ),
            );
            run(&tree).expect("logically test-only cfg must be excluded");
            remove(tree);
        }

        let tree = fixture();
        write(
            &tree,
            "crates/mvm-unrelated/src/cfg_feature.rs",
            "#[cfg(all(test, feature = \"x\"))]\n\
             fn helper() { restore_checkpoint(); }\n",
        );
        run(&tree).expect("test-only cfg literals must survive structural parsing");
        remove(tree);
    }

    #[test]
    fn untyped_full_restorer_callback_or_tag_is_rejected() {
        for source in [
            "fn fork(restore: &ForkRestore<'_>) {}\n",
            "fn fork() { VmFullForkRestorer::Firecracker(&|child| restore(child)); }\n",
        ] {
            let tree = fixture();
            write(&tree, "crates/mvm-client/src/other.rs", source);
            let error = run(&tree).expect_err("untyped restorer must fail");
            assert!(error.to_string().contains("ForkRest"), "{error:#}");
            remove(tree);
        }
    }

    #[test]
    fn third_checkpoint_or_sealed_resume_owner_is_rejected() {
        for (path, source, needle) in [
            (
                "crates/mvm-client/src/other.rs",
                "fn extra() { restore_checkpoint(); }\n",
                "third same-identity",
            ),
            (
                "crates/mvm-unrelated/src/lib.rs",
                "fn extra() { restore_checkpoint(); }\n",
                "third same-identity",
            ),
            (
                "crates/mvm-unrelated/src/lib.rs",
                "fn extra() { restore_same_identity_checkpoint(); }\n",
                "outside its client owner",
            ),
            (
                "crates/mvm-client/src/other.rs",
                "fn extra() { verify_and_resume(); }\n",
                "third sealed-resume",
            ),
            (
                "crates/mvm-client/src/local/new_owner.rs",
                "fn extra() { verify_and_resume(); }\n",
                "third sealed-resume",
            ),
            (
                "crates/mvm-client/src/local_extra.rs",
                "fn extra() { verify_and_resume(); }\n",
                "third sealed-resume",
            ),
        ] {
            let tree = fixture();
            write(&tree, path, source);
            let error = run(&tree).expect_err("third same-identity owner must fail");
            assert!(error.to_string().contains(needle), "{error:#}");
            remove(tree);
        }
    }

    #[test]
    fn fresh_dispatch_in_a_same_identity_owner_is_rejected() {
        for (path, source, needle) in [
            (
                SEALED_RESUME_OWNER,
                "fn verify_and_resume_from_dir() { guarded_load_resume(); \
                 start_custodied_verified_release(); }\n",
                "start_custodied_verified_release",
            ),
            (
                CLIENT_VM_FULL_OWNER,
                "pub fn restore_vm_full_checkpoint(backend: AnyBackend, config: Config) { \
                 restore_same_identity_checkpoint(); backend.start(&config); }\n",
                "backend `start`",
            ),
            (
                SEALED_RESUME_OWNER,
                "fn verify_and_resume_from_dir(backend: AnyBackend, config: Config) { \
                 guarded_load_resume(); backend.start_custodied(&config, Vec::new()); }\n",
                "start_custodied",
            ),
            (
                CLIENT_VM_FULL_OWNER,
                "pub fn restore_vm_full_checkpoint() { \
                 restore_same_identity_checkpoint(); fork_vm_full(); }\n",
                "fork_vm_full",
            ),
        ] {
            let tree = fixture();
            write(&tree, path, source);
            let error = run(&tree).expect_err("same-identity owner cannot mint fresh authority");
            assert!(error.to_string().contains(needle), "{error:#}");
            remove(tree);
        }
    }

    #[test]
    fn multiline_and_aliased_checkpoint_reexports_are_rejected() {
        let tree = fixture();
        write(
            &tree,
            CLIENT_CHECKPOINT,
            "const NOTE: &str = \"pub use fake::{RestoreParams, fork_vm_full};\";\n\
             pub mod nested {\n\
                 pub use mvm_runtime::checkpoint::{\n\
                     RestoreParams as PublicRestore,\n\
                     RestoredChild as PublicChild,\n\
                     fork_vm_full as fork_full,\n\
                     restore_checkpoint as resume_checkpoint,\n\
                     restore_same_identity_checkpoint as typed_resume,\n\
                     vm_full_restorer_for as select_restorer,\n\
                 };\n\
                 pub use mvm_runtime::firecracker::FcForkRestorer as FcRestore;\n\
                 pub use mvm_runtime::hvf_restore::HvfForkRestorer as HvfRestore;\n\
                 pub use mvm_runtime::checkpoint::*;\n\
                 #[cfg(test)] pub mod tests {\n\
                     pub use ignored::OnlyInTests;\n\
                 }\n\
             }\n\
             pub fn restore_vm_full_checkpoint() { \
                 mvm_runtime::checkpoint::restore_same_identity_checkpoint(); }\n",
        );
        let error = run(&tree).expect_err("raw checkpoint APIs cannot be reexported");
        let rendered = error.to_string();
        for forbidden in [
            "RestoreParams",
            "RestoredChild",
            "fork_vm_full",
            "restore_checkpoint",
            "restore_same_identity_checkpoint",
            "vm_full_restorer_for",
            "FcForkRestorer",
            "HvfForkRestorer",
        ] {
            assert!(rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("glob reexport"), "{rendered}");
        remove(tree);
    }

    #[test]
    fn public_reexports_use_the_structural_test_only_filter() {
        for cfg in ["not(test)", "any(test, unix)"] {
            let tree = fixture();
            write(
                &tree,
                CLIENT_CHECKPOINT,
                &format!(
                    "#[cfg({cfg})]\n\
                     pub use mvm_runtime::checkpoint::RestoreParams;\n\
                     pub fn restore_vm_full_checkpoint() {{ \
                     restore_same_identity_checkpoint(); }}\n"
                ),
            );
            let error = run(&tree).expect_err("production-capable reexport must fail");
            assert!(error.to_string().contains("RestoreParams"), "{error:#}");
            remove(tree);
        }

        let tree = fixture();
        write(
            &tree,
            CLIENT_CHECKPOINT,
            "#[cfg(all(test, unix))]\n\
             pub use mvm_runtime::checkpoint::RestoreParams;\n\
             pub fn restore_vm_full_checkpoint() { restore_same_identity_checkpoint(); }\n",
        );
        run(&tree).expect("logically test-only reexport must be excluded");
        remove(tree);
    }

    #[test]
    fn malformed_original_rust_fails_the_public_use_gate_closed() {
        let tree = fixture();
        write(
            &tree,
            CLIENT_CHECKPOINT,
            "pub use mvm_runtime::checkpoint::{RestoreParams;\n",
        );
        let error = run(&tree).expect_err("unparseable source cannot bypass reexport checks");
        assert!(
            error.to_string().contains("parse failed closed"),
            "{error:#}"
        );
        remove(tree);
    }

    #[test]
    fn typed_fresh_fork_and_exact_same_identity_seams_are_accepted() {
        let tree = fixture();
        run(&tree).expect("typed fresh fork and two same-identity owners are valid");
        remove(tree);
    }

    #[test]
    fn comments_strings_and_tests_do_not_create_dispatch_owners() {
        let tree = fixture();
        write(
            &tree,
            "crates/mvm-cli/src/notes.rs",
            "// restore_checkpoint start_prepared\n\
             const NOTE: &str = \"verify_and_resume claim_standby_via_runner\";\n\
             #[cfg(test)] mod tests { fn bypass() { restore_checkpoint(); } }\n",
        );
        write(
            &tree,
            CLIENT_CHECKPOINT,
            "const NOTE: &str = \"pub use fake::RestoreParams; backend.start();\";\n\
             pub fn restore_vm_full_checkpoint() { restore_same_identity_checkpoint(); }\n\
             #[cfg(test)] mod tests {\n\
                 pub mod nested {\n\
                     pub use mvm_runtime::checkpoint::{RestoreParams, restore_checkpoint};\n\
                     fn bypass(backend: AnyBackend, config: Config) { backend.start(&config); }\n\
                 }\n\
             }\n",
        );
        run(&tree).expect("non-production text cannot create authority");
        remove(tree);
    }

    #[test]
    fn raw_template_restore_checks_remain_enforced() {
        let tree = fixture();
        write(
            &tree,
            "crates/mvm-cli/src/template.rs",
            "fn bypass() { restore_from_template_snapshot(); let _ = FlakeRunConfig; }\n",
        );
        let error = run(&tree).expect_err("raw template restore must fail");
        assert!(error.to_string().contains("FlakeRunConfig"), "{error:#}");
        assert!(
            error.to_string().contains("restore_from_template_snapshot"),
            "{error:#}"
        );
        remove(tree);
    }

    fn fixture() -> std::path::PathBuf {
        let tree = std::env::temp_dir().join(format!(
            "mvm-workload-dispatch-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tree);
        write(
            &tree,
            CLI_VM_FULL_OWNER,
            "fn restore() { restore_vm_full_checkpoint(); }\n",
        );
        write(
            &tree,
            CLIENT_VM_FULL_OWNER,
            "pub fn restore_vm_full_checkpoint() { restore_same_identity_checkpoint(); }\n",
        );
        write(
            &tree,
            RUNTIME_CHECKPOINT,
            "pub fn restore_same_identity_checkpoint() { \
             let meta = read_meta(); authenticate(&meta); \
             let restore = vm_full_restorer_for(&meta); \
             let target_vm = meta.vm_name.clone(); dispatch(target_vm, restore); }\n\
             #[cfg(test)] fn restore_checkpoint() {}\n",
        );
        write(
            &tree,
            SEALED_RESUME_OWNER,
            "pub fn verify_and_resume() { verify_and_resume_from_dir(); }\n\
             pub fn verify_and_resume_from_dir() { guarded_load_resume(); }\n",
        );
        write(
            &tree,
            "crates/mvm-client/src/local/resume.rs",
            "fn resume() { verify_and_resume(); }\n",
        );
        write(
            &tree,
            "crates/mvm-client/src/local.rs",
            "fn resume() { verify_and_resume(); }\n",
        );
        write(
            &tree,
            "crates/mvm-vmm/src/snapshot.rs",
            "pub fn guarded_load_resume() {}\n",
        );
        write(
            &tree,
            CLIENT_BOOT,
            "pub(crate) fn start_prepared_owned() {}\n",
        );
        write(
            &tree,
            CLIENT_FULL_FORK,
            "fn dispatch(bound: Bound) { bound.dispatch_firecracker(&FcForkRestorer); \
             bound.dispatch_hvf(&HvfForkRestorer); }\n",
        );
        write(
            &tree,
            HOSTD_FULL_FORK,
            "enum VmFullForkRestorer<'a> { \
             Firecracker(&'a mvm_runtime::firecracker::FcForkRestorer), \
             Hvf(&'a mvm_runtime::hvf_restore::HvfForkRestorer) }\n",
        );
        tree
    }

    fn write(tree: &Path, rel: &str, source: &str) {
        let path = tree.join(rel);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        std::fs::write(path, source).expect("fixture source");
    }

    fn remove(tree: std::path::PathBuf) {
        std::fs::remove_dir_all(tree).expect("remove fixture");
    }
}
