//! Smart contract upgrade checks: whether a package may upgrade the earlier packages of the same name, as Canton 3.7.2
//! decides when it vets a package (`PackageUpgradeValidator.validateUpgrade`, which runs Daml-LF
//! `TypecheckUpgrades` on each pair of consecutive versions of a package name).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::proto::daml_lf_2::Package;
use crate::typecheck::{
    decode_choice, decode_data_type, decode_type, dotted_string, err, interned_str,
    resolve_type_con_id, DecodedDataCons, Ident, LKind, LType, TypeError,
};

/// A package version: dot-separated non-negative integers ordered segment by segment (`Ref.PackageVersion`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageVersion(Vec<u64>);

impl PackageVersion {
    /// Parses `1.0.2`; `None` for a text that is not a package version.
    pub fn parse(s: &str) -> Option<Self> {
        let segments = s
            .split('.')
            .map(|seg| {
                let well_formed = !seg.is_empty()
                    && seg.bytes().all(|b| b.is_ascii_digit())
                    && (seg == "0" || !seg.starts_with('0'));
                well_formed.then(|| seg.parse().ok()).flatten()
            })
            .collect::<Option<Vec<u64>>>()?;
        Some(Self(segments))
    }
}

/// The name and version of a package: all an upgrade check needs of the packages a type refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMeta {
    pub name: String,
    pub version: PackageVersion,
}

/// A package as `pkgId (name vVersion)`, the way Canton names it in its errors (`PkgIdWithNameAndVersion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub package_id: String,
    pub name: String,
    pub version: String,
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} v{})", self.package_id, self.name, self.version)
    }
}

/// Where a record or variant sits in its module, which an upgrade may not change (`UpgradedRecordOrigin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOrigin {
    TemplateBody(String),
    TemplateChoiceInput {
        template: String,
        choice: String,
    },
    /// [CANTON-NOTE: SEMANTICS] The constructor's type is compared without its package (`unifyIdentifier`), so it
    /// is not kept.
    VariantConstructor {
        datatype: String,
        variant_module: String,
        variant_name: String,
    },
    TopLevel(String),
}

impl fmt::Display for RecordOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TemplateBody(t) => write!(f, "template {t}"),
            Self::TemplateChoiceInput { template, choice } => {
                write!(f, "input type of choice {choice} on template {template}")
            }
            Self::VariantConstructor {
                datatype,
                variant_name,
                ..
            } => write!(
                f,
                "variant constructor {variant_name} from variant {datatype}"
            ),
            Self::TopLevel(d) => write!(f, "data type {d}"),
        }
    }
}

/// Why a package is not a valid upgrade of another, with Daml's messages (`UpgradeError.Error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpgradeError {
    #[error("Module {0} appears in package that is being upgraded, but does not appear in the upgrading package.")]
    MissingModule(String),
    #[error("Template {0} appears in package that is being upgraded, but does not appear in the upgrading package.")]
    MissingTemplate(String),
    #[error("Data type {0} appears in package that is being upgraded, but does not appear in the upgrading package.")]
    MissingDataCon(String),
    #[error("Choice {0} appears in package that is being upgraded, but does not appear in the upgrading package.")]
    MissingChoice(String),
    #[error("The upgraded template {0} cannot change its key type.")]
    TemplateChangedKeyType(String),
    #[error("The upgraded template {0} cannot remove its key.")]
    TemplateRemovedKey(String),
    #[error("The upgraded template {0} cannot add a key.")]
    TemplateAddedKey(String),
    #[error("The upgraded choice {0} cannot change its return type.")]
    ChoiceChangedReturnType(String),
    #[error("The record {name} has changed origin from {past} to {present}")]
    RecordChangedOrigin {
        name: String,
        past: Box<RecordOrigin>,
        present: Box<RecordOrigin>,
    },
    #[error("The upgraded data type {name} has changed from a {past} to a {present}. Datatypes cannot change variety via upgrades.")]
    MismatchDataConsVariety {
        name: String,
        past: &'static str,
        present: &'static str,
    },
    #[error("The upgraded {0} is missing some of its original fields.")]
    RecordFieldsMissing(RecordOrigin),
    #[error("The upgraded {0} has changed the types of some of its original fields.")]
    RecordFieldsExistingChanged(RecordOrigin),
    #[error("The upgraded {0} has added new fields, but those fields are not Optional.")]
    RecordFieldsNewNonOptional(RecordOrigin),
    #[error("The upgraded {0} has changed the order of its fields - any new fields must be added at the end of the record.")]
    RecordFieldsOrderChanged(RecordOrigin),
    #[error("The upgraded {0} has removed an existing variant.")]
    VariantRemovedVariant(RecordOrigin),
    #[error("The upgraded {0} has changed the type of a variant.")]
    VariantChangedVariantType(RecordOrigin),
    #[error("The upgraded {0} has changed the order of its variants - any new variant must be added at the end of the variant.")]
    VariantVariantsOrderChanged(RecordOrigin),
    #[error("The upgraded {0} has added a field.")]
    VariantAddedVariantField(RecordOrigin),
    #[error("The upgraded {0} has removed an existing variant.")]
    EnumRemovedVariant(RecordOrigin),
    #[error("The upgraded {0} has changed the order of its variants - any new variant must be added at the end of the enum.")]
    EnumVariantsOrderChanged(RecordOrigin),
    #[error("The upgraded package uses an older LF version ({present} < {past})")]
    DecreasingLfVersion { past: String, present: String },
    #[error("Implementation of interface {iface} by template {template} appears in package that is being upgraded, but does not appear in this package.")]
    MissingImplementation { template: String, iface: String },
    #[error("The upgraded {0} was serializable and is now unserializable. Datatypes cannot change their serializability via upgrades.")]
    DatatypeBecameUnserializable(RecordOrigin),
    #[error("The upgraded {0} has changed the number of type variables it has.")]
    DifferentParamsCount(RecordOrigin),
    #[error("The upgraded {0} has changed the kind of one of its type variables.")]
    DifferentParamsKinds(RecordOrigin),
}

/// A vetting refused by the upgrade checks, with the Canton error it is (`ParticipantTopologyManagerError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpgradeCheckError {
    /// `KNOWN_PACKAGE_VERSION`.
    #[error("Tried to vet two packages with the same name and version: {first} and {second}.")]
    KnownPackageVersion {
        first: Box<PackageRef>,
        second: Box<PackageRef>,
    },
    /// `NOT_VALID_UPGRADE_PACKAGE`.
    #[error("Upgrade checks indicate that {upgrading} cannot be an upgrade of {upgraded}. Reason: {reason}")]
    NotValidUpgrade {
        upgraded: Box<PackageRef>,
        upgrading: Box<PackageRef>,
        reason: UpgradeError,
    },
}

impl UpgradeCheckError {
    /// The Canton error code; both are `InvalidIndependentOfSystemState` (category 8, `INVALID_ARGUMENT`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::KnownPackageVersion { .. } => "KNOWN_PACKAGE_VERSION",
            Self::NotValidUpgrade { .. } => "NOT_VALID_UPGRADE_PACKAGE",
        }
    }
}

#[derive(Debug, Clone)]
struct DataTypeSig {
    serializable: bool,
    params: Vec<(String, LKind)>,
    cons: DecodedDataCons,
}

#[derive(Debug, Clone)]
struct TemplateSig {
    /// Choice name to return type.
    choices: BTreeMap<String, LType>,
    key: Option<LType>,
    implements: BTreeSet<Ident>,
}

#[derive(Debug, Clone, Default)]
struct ModuleSig {
    data_types: BTreeMap<String, DataTypeSig>,
    templates: BTreeMap<String, TemplateSig>,
    interfaces: BTreeSet<String>,
    exceptions: BTreeSet<String>,
}

/// What the upgrade checks read of a package: its metadata and the signatures of its definitions.
#[derive(Debug, Clone)]
pub struct PackageSignature {
    pub package_id: String,
    pub name: String,
    pub version: String,
    order: PackageVersion,
    /// The LF minor ordinal (`dev` last).
    lf_rank: u32,
    lf_version: String,
    deps: BTreeSet<String>,
    modules: BTreeMap<String, ModuleSig>,
}

impl PackageSignature {
    /// Reads the signature of a decoded package whose LF version is `lf_version` (`"2.1"`, `"2.dev"`).
    pub fn from_package(
        package_id: &str,
        package: &Package,
        lf_version: &str,
    ) -> Result<Self, TypeError> {
        let id = package_id;
        let meta = package
            .metadata
            .as_ref()
            .ok_or_else(|| err(id, "EUpgrade", "package has no metadata"))?;
        let name = interned_str(id, package, meta.name_interned_str, "metadata.name")?.to_string();
        let version =
            interned_str(id, package, meta.version_interned_str, "metadata.version")?.to_string();
        let order = PackageVersion::parse(&version)
            .ok_or_else(|| err(id, "EUpgrade", format!("invalid package version {version}")))?;
        let lf_rank = lf_version
            .strip_prefix("2.")
            .and_then(crate::features::minor_rank)
            .ok_or_else(|| err(id, "EUpgrade", format!("unknown LF version {lf_version}")))?;
        let mut modules = BTreeMap::new();
        for module in &package.modules {
            let mod_name = dotted_string(id, package, module.name_interned_dname, "Module.name")?;
            let mut sig = ModuleSig::default();
            for def in &module.data_types {
                let (name, dt) = decode_data_type(id, package, &mod_name, def)?;
                sig.data_types.insert(
                    name,
                    DataTypeSig {
                        serializable: dt.serializable,
                        params: dt.params,
                        cons: dt.cons,
                    },
                );
            }
            for template in &module.templates {
                let name = dotted_string(id, package, template.tycon_interned_dname, "template")?;
                let mut choices = BTreeMap::new();
                for choice in &template.choices {
                    let c = decode_choice(id, package, choice)?;
                    choices.insert(c.name, c.ret_type);
                }
                let key = match &template.key {
                    Some(k) => Some(decode_type(id, package, k.r#type.as_ref(), 0)?),
                    None => None,
                };
                let mut implements = BTreeSet::new();
                for imp in &template.implements {
                    implements.insert(resolve_type_con_id(id, package, imp.interface.as_ref())?);
                }
                sig.templates.insert(
                    name,
                    TemplateSig {
                        choices,
                        key,
                        implements,
                    },
                );
            }
            for iface in &module.interfaces {
                sig.interfaces.insert(dotted_string(
                    id,
                    package,
                    iface.tycon_interned_dname,
                    "interface",
                )?);
            }
            for exception in &module.exceptions {
                sig.exceptions.insert(dotted_string(
                    id,
                    package,
                    exception.name_interned_dname,
                    "exception",
                )?);
            }
            modules.insert(mod_name, sig);
        }
        Ok(Self {
            package_id: id.to_string(),
            name,
            version,
            order,
            lf_rank,
            lf_version: lf_version.to_string(),
            deps: crate::archive::referenced_package_ids(id, package)
                .into_iter()
                .collect(),
            modules,
        })
    }

    /// The signature of every package of a DAR, by package id.
    pub fn of_dar(dar: &crate::LoadedDar) -> Result<BTreeMap<String, PackageSignature>, TypeError> {
        let mut out = BTreeMap::new();
        for (id, package) in &dar.packages {
            let lf = dar.package_versions.get(id).map_or("2.1", String::as_str);
            out.insert(id.clone(), Self::from_package(id, package, lf)?);
        }
        Ok(out)
    }

    pub fn meta(&self) -> PackageMeta {
        PackageMeta {
            name: self.name.clone(),
            version: self.order.clone(),
        }
    }

    fn reference(&self) -> Box<PackageRef> {
        Box::new(PackageRef {
            package_id: self.package_id.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
        })
    }

    /// Packages without templates, interfaces or serializable data types are not upgrade-checked
    /// (`isUtilityPackage`).
    fn is_utility(&self) -> bool {
        self.modules.values().all(|m| {
            m.templates.is_empty()
                && m.interfaces.is_empty()
                && m.data_types.values().all(|d| !d.serializable)
        })
    }

    /// `supportsUpgrades`: every LF 2 package except utility packages and the Daml standard library.
    ///
    /// [CANTON-NOTE: LIMITATION] Canton exempts `daml-prim` and `daml-stdlib` by a pinned list of package ids and
    /// refuses any other non-utility package of those names (`DAML_PRIM_NOT_UTILITY_PACKAGE`); here both names are
    /// exempt whatever their id, and that refusal is not made.
    fn supports_upgrades(&self) -> bool {
        !self.is_utility() && self.name != "daml-prim" && self.name != "daml-stdlib"
    }
}

/// Checks the lineages a vetting touches, as `PackageUpgradeValidator.validateUpgrade(newPackagesToVet,
/// targetVettedPackages, storedPackageMap)` does: for the name of every new package and of its dependencies, the
/// packages of that name in `vetted` sorted by version, one by one against the next.
///
/// `vetted` holds the signatures of the packages vetted after the change (the new ones included); `known` names the
/// other packages types may refer to.
pub fn validate_upgrade(
    new_packages: &BTreeSet<String>,
    vetted: &BTreeMap<String, PackageSignature>,
    known: &BTreeMap<String, PackageMeta>,
) -> Result<(), UpgradeCheckError> {
    let mut metas = known.clone();
    metas.extend(vetted.iter().map(|(id, sig)| (id.clone(), sig.meta())));
    for name in names_in_topological_order(new_packages, vetted) {
        let mut lineage: Vec<&PackageSignature> =
            vetted.values().filter(|sig| sig.name == name).collect();
        lineage.sort_by(|a, b| (&a.order, &a.package_id).cmp(&(&b.order, &b.package_id)));
        let upgrading: Vec<&PackageSignature> = lineage
            .into_iter()
            .filter(|sig| sig.supports_upgrades())
            .collect();
        for pair in upgrading.windows(2) {
            if let [first, second] = pair {
                if first.order == second.order {
                    return Err(UpgradeCheckError::KnownPackageVersion {
                        first: first.reference(),
                        second: second.reference(),
                    });
                }
            }
        }
        for pair in upgrading.windows(2) {
            if let [past, present] = pair {
                typecheck_upgrades(&metas, past, present).map_err(|reason| {
                    UpgradeCheckError::NotValidUpgrade {
                        upgraded: past.reference(),
                        upgrading: present.reference(),
                        reason,
                    }
                })?;
            }
        }
    }
    Ok(())
}

/// The package names of `roots` and of their dependencies in `pool`, dependencies first
/// (`dependenciesInTopologicalOrder`), each once.
fn names_in_topological_order(
    roots: &BTreeSet<String>,
    pool: &BTreeMap<String, PackageSignature>,
) -> Vec<String> {
    enum Step<'a> {
        Enter(&'a str),
        Leave(&'a PackageSignature),
    }
    let mut visited = BTreeSet::new();
    let mut names = Vec::new();
    let mut stack: Vec<Step<'_>> = roots.iter().rev().map(|r| Step::Enter(r)).collect();
    while let Some(step) = stack.pop() {
        match step {
            Step::Enter(id) => {
                let Some(sig) = pool.get(id) else { continue };
                if !visited.insert(id) {
                    continue;
                }
                stack.push(Step::Leave(sig));
                stack.extend(sig.deps.iter().rev().map(|d| Step::Enter(d)));
            }
            Step::Leave(sig) => {
                if !names.contains(&sig.name) {
                    names.push(sig.name.clone());
                }
            }
        }
    }
    names
}

/// Binder depth of the type variables in scope (`Env`).
#[derive(Default)]
struct Env {
    depth: BTreeMap<String, usize>,
}

impl Env {
    fn with_params(params: &[(String, LKind)]) -> Self {
        let mut env = Self::default();
        for (i, (name, _)) in params.iter().enumerate() {
            env.depth.insert(name.clone(), i);
        }
        env
    }
}

/// Daml-LF `TypecheckUpgrades.typecheckUpgrades`: is `present` a valid upgrade of `past`.
pub fn typecheck_upgrades(
    metas: &BTreeMap<String, PackageMeta>,
    past: &PackageSignature,
    present: &PackageSignature,
) -> Result<(), UpgradeError> {
    Checker { metas }.check(past, present)
}

struct Checker<'a> {
    metas: &'a BTreeMap<String, PackageMeta>,
}

fn variety(cons: &DecodedDataCons) -> &'static str {
    match cons {
        DecodedDataCons::Record(_) => "record",
        DecodedDataCons::Variant(_) => "variant",
        DecodedDataCons::Enum(_) => "enum",
        DecodedDataCons::Interface => "interface",
    }
}

fn names<T>(entries: &[(String, T)]) -> impl Iterator<Item = &str> {
    entries.iter().map(|(n, _)| n.as_str())
}

/// A pair at the same position with different names (`past.zip(present).filter(past != present)`).
fn order_changed<'n>(
    past: impl Iterator<Item = &'n str>,
    present: impl Iterator<Item = &'n str>,
) -> bool {
    past.zip(present).any(|(a, b)| a != b)
}

fn fail_if(cond: bool, e: impl FnOnce() -> UpgradeError) -> Result<(), UpgradeError> {
    if cond {
        Err(e())
    } else {
        Ok(())
    }
}

impl Checker<'_> {
    fn check(
        &self,
        past: &PackageSignature,
        present: &PackageSignature,
    ) -> Result<(), UpgradeError> {
        fail_if(past.lf_rank > present.lf_rank, || {
            UpgradeError::DecreasingLfVersion {
                past: past.lf_version.clone(),
                present: present.lf_version.clone(),
            }
        })?;
        if let Some(name) = past
            .modules
            .keys()
            .find(|m| !present.modules.contains_key(*m))
        {
            return Err(UpgradeError::MissingModule(name.clone()));
        }
        for (name, module) in &past.modules {
            if let Some(next) = present.modules.get(name) {
                self.check_module(module, next)?;
            }
        }
        Ok(())
    }

    fn check_module(&self, past: &ModuleSig, present: &ModuleSig) -> Result<(), UpgradeError> {
        if let Some(name) = past
            .templates
            .keys()
            .find(|t| !present.templates.contains_key(*t))
        {
            return Err(UpgradeError::MissingTemplate(name.clone()));
        }
        for (name, template) in &past.templates {
            if let Some(next) = present.templates.get(name) {
                self.check_template(name, template, next)?;
            }
        }
        // [CANTON-NOTE: SEMANTICS] Continued interfaces and exceptions are not refused in 3.7.2: the
        // `TriedToUpgradeIface` / `TriedToUpgradeException` failures are commented out behind compiler flags.
        for (tpl, template) in &past.templates {
            for iface in &template.implements {
                let kept = present
                    .templates
                    .get(tpl)
                    .is_some_and(|t| t.implements.contains(iface));
                if !kept {
                    return Err(UpgradeError::MissingImplementation {
                        template: tpl.clone(),
                        iface: format!("{}:{}:{}", iface.pkg, iface.module, iface.name),
                    });
                }
            }
        }
        let owned =
            |m: &ModuleSig, name: &str| m.interfaces.contains(name) || m.exceptions.contains(name);
        let unowned = |m: &ModuleSig, name: &String| !owned(m, name);
        if let Some(name) = past.data_types.iter().find_map(|(name, dt)| {
            (unowned(past, name)
                && dt.serializable
                && !present
                    .data_types
                    .get(name)
                    .is_some_and(|_| unowned(present, name)))
            .then_some(name)
        }) {
            return Err(UpgradeError::MissingDataCon(name.clone()));
        }
        for (name, dt) in &past.data_types {
            if !unowned(past, name) {
                continue;
            }
            if let Some(next) = present
                .data_types
                .get(name)
                .filter(|_| unowned(present, name))
            {
                self.check_datatype(name, (past, dt), (present, next))?;
            }
        }
        Ok(())
    }

    fn check_template(
        &self,
        name: &str,
        past: &TemplateSig,
        present: &TemplateSig,
    ) -> Result<(), UpgradeError> {
        if let Some(choice) = past
            .choices
            .keys()
            .find(|c| !present.choices.contains_key(*c))
        {
            return Err(UpgradeError::MissingChoice(choice.clone()));
        }
        for (choice, ret) in &past.choices {
            if let Some(next) = present.choices.get(choice) {
                fail_if(
                    !self.same_type(&Env::default(), ret, &Env::default(), next),
                    || UpgradeError::ChoiceChangedReturnType(choice.clone()),
                )?;
            }
        }
        match (&past.key, &present.key) {
            (None, None) => Ok(()),
            (Some(a), Some(b)) => fail_if(
                !self.same_type(&Env::default(), a, &Env::default(), b),
                || UpgradeError::TemplateChangedKeyType(name.to_string()),
            ),
            (Some(_), None) => Err(UpgradeError::TemplateRemovedKey(name.to_string())),
            (None, Some(_)) => Err(UpgradeError::TemplateAddedKey(name.to_string())),
        }
    }

    /// `ModuleWithMetadata.dataTypeOrigin`.
    fn origin(module: &ModuleSig, name: &str) -> RecordOrigin {
        if module.templates.contains_key(name) {
            return RecordOrigin::TemplateBody(name.to_string());
        }
        let (prefix, last) = match name.rsplit_once('.') {
            Some((p, l)) => (Some(p), l),
            None => (None, name),
        };
        // a choice argument is named after the choice, in the template's module prefix
        for (template, sig) in &module.templates {
            let template_prefix = template.rsplit_once('.').map(|(p, _)| p);
            if template_prefix == prefix && sig.choices.contains_key(last) {
                return RecordOrigin::TemplateChoiceInput {
                    template: template.clone(),
                    choice: last.to_string(),
                };
            }
        }
        // a variant constructor's record is named `Variant.Constructor`
        if let Some(datatype) = prefix {
            if let Some(DataTypeSig {
                cons: DecodedDataCons::Variant(variants),
                ..
            }) = module.data_types.get(datatype)
            {
                let con = variants
                    .iter()
                    .find(|(n, _)| n == last)
                    .and_then(|(_, ty)| left_most_tycon(ty));
                if let Some(con) = con {
                    return RecordOrigin::VariantConstructor {
                        datatype: datatype.to_string(),
                        variant_module: con.module.clone(),
                        variant_name: con.name.clone(),
                    };
                }
            }
        }
        RecordOrigin::TopLevel(name.to_string())
    }

    fn check_datatype(
        &self,
        name: &str,
        (past_module, past): (&ModuleSig, &DataTypeSig),
        (present_module, present): (&ModuleSig, &DataTypeSig),
    ) -> Result<(), UpgradeError> {
        let origin = Self::origin(present_module, name);
        match (past.serializable, present.serializable) {
            (true, false) => return Err(UpgradeError::DatatypeBecameUnserializable(origin)),
            (false, _) => return Ok(()),
            (true, true) => {}
        }
        let past_origin = Self::origin(past_module, name);
        if past_origin != origin {
            return Err(UpgradeError::RecordChangedOrigin {
                name: name.to_string(),
                past: Box::new(past_origin),
                present: Box::new(origin),
            });
        }
        fail_if(past.params.len() != present.params.len(), || {
            UpgradeError::DifferentParamsCount(origin.clone())
        })?;
        let kinds = |dt: &DataTypeSig| dt.params.iter().map(|(_, k)| k.clone()).collect::<Vec<_>>();
        fail_if(kinds(past) != kinds(present), || {
            UpgradeError::DifferentParamsKinds(origin.clone())
        })?;
        let past_env = Env::with_params(&past.params);
        let present_env = Env::with_params(&present.params);
        let same = |a: &LType, b: &LType| self.same_type(&past_env, a, &present_env, b);
        match (&past.cons, &present.cons) {
            (DecodedDataCons::Record(a), DecodedDataCons::Record(b)) => {
                Self::check_fields(origin, a, b, same)
            }
            (DecodedDataCons::Variant(a), DecodedDataCons::Variant(b)) => {
                let present_types: BTreeMap<&str, &LType> =
                    b.iter().map(|(n, t)| (n.as_str(), t)).collect();
                fail_if(
                    a.iter()
                        .any(|(n, _)| !present_types.contains_key(n.as_str())),
                    || UpgradeError::VariantRemovedVariant(origin.clone()),
                )?;
                let changed = a.iter().any(|(n, t)| {
                    present_types
                        .get(n.as_str())
                        .is_some_and(|next| !same(t, next))
                });
                fail_if(changed, || {
                    UpgradeError::VariantChangedVariantType(origin.clone())
                })?;
                fail_if(order_changed(names(a), names(b)), || {
                    UpgradeError::VariantVariantsOrderChanged(origin.clone())
                })
            }
            (DecodedDataCons::Enum(a), DecodedDataCons::Enum(b)) => {
                fail_if(a.iter().any(|c| !b.contains(c)), || {
                    UpgradeError::EnumRemovedVariant(origin.clone())
                })?;
                fail_if(
                    order_changed(a.iter().map(String::as_str), b.iter().map(String::as_str)),
                    || UpgradeError::EnumVariantsOrderChanged(origin.clone()),
                )
            }
            (DecodedDataCons::Interface, DecodedDataCons::Interface) => Ok(()),
            (a, b) => Err(UpgradeError::MismatchDataConsVariety {
                name: name.to_string(),
                past: variety(a),
                present: variety(b),
            }),
        }
    }

    /// `checkFields`: no field removed, none retyped, new ones `Optional`, the old ones first and in order.
    fn check_fields(
        origin: RecordOrigin,
        past: &[(String, LType)],
        present: &[(String, LType)],
        same: impl Fn(&LType, &LType) -> bool,
    ) -> Result<(), UpgradeError> {
        let present_types: BTreeMap<&str, &LType> =
            present.iter().map(|(n, t)| (n.as_str(), t)).collect();
        let past_names: BTreeSet<&str> = names(past).collect();
        fail_if(
            past.iter()
                .any(|(n, _)| !present_types.contains_key(n.as_str())),
            || UpgradeError::RecordFieldsMissing(origin.clone()),
        )?;
        let changed = past.iter().any(|(n, t)| {
            present_types
                .get(n.as_str())
                .is_some_and(|next| !same(t, next))
        });
        fail_if(changed, || {
            UpgradeError::RecordFieldsExistingChanged(origin.clone())
        })?;
        let new_non_optional = present
            .iter()
            .any(|(n, t)| !past_names.contains(n.as_str()) && !is_optional(t));
        fail_if(new_non_optional, || match origin {
            RecordOrigin::VariantConstructor { .. } => {
                UpgradeError::VariantAddedVariantField(origin.clone())
            }
            _ => UpgradeError::RecordFieldsNewNonOptional(origin.clone()),
        })?;
        fail_if(order_changed(names(past), names(present)), || {
            UpgradeError::RecordFieldsOrderChanged(origin.clone())
        })
    }

    /// `checkIdentifiers`: same qualified name, and either the same package or a later version of the same name.
    fn same_identifier(&self, past: &Ident, present: &Ident) -> bool {
        let compatible_packages = match (self.metas.get(&past.pkg), self.metas.get(&present.pkg)) {
            (None, None) => past.pkg == present.pkg,
            (Some(a), Some(b)) => a.name == b.name && a.version <= b.version,
            _ => false,
        };
        past.module == present.module && past.name == present.name && compatible_packages
    }

    /// `checkTypeList`: structural equality up to type-variable binder depth and upgradable type constructors.
    fn same_type(&self, past_env: &Env, past: &LType, present_env: &Env, present: &LType) -> bool {
        let mut pending = vec![(past, present)];
        while let Some((a, b)) = pending.pop() {
            let same = match (a, b) {
                (LType::Var(x), LType::Var(y)) => {
                    matches!((past_env.depth.get(x), present_env.depth.get(y)), (Some(i), Some(j)) if i == j)
                }
                (LType::Nat(n), LType::Nat(m)) => n == m,
                (LType::Con(c), LType::Con(d)) => self.same_identifier(c, d),
                (LType::App(f1, a1), LType::App(f2, a2)) => {
                    pending.push((a1, a2));
                    pending.push((f1, f2));
                    true
                }
                (LType::Builtin(x), LType::Builtin(y)) => x == y,
                _ => false,
            };
            if !same {
                return false;
            }
        }
        true
    }
}

fn is_optional(ty: &LType) -> bool {
    matches!(ty, LType::App(f, _) if matches!(**f, LType::Builtin(crate::proto::daml_lf_2::BuiltinType::Optional)))
}

fn left_most_tycon(ty: &LType) -> Option<&Ident> {
    let mut t = ty;
    loop {
        match t {
            LType::App(f, _) => t = f,
            LType::Con(id) => return Some(id),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::daml_lf_2::{def_data_type, r#type, BuiltinType, DefDataType, Type};

    fn dar(name: &str) -> crate::LoadedDar {
        crate::load_dar_file(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/oracle/upgrade")
                .join(name),
        )
        .expect("fixture dar")
    }

    /// The main package of a fixture DAR, its id, and its LF version.
    fn main_package(name: &str) -> (String, Package, String) {
        let d = dar(name);
        let id = d.archive.main_package_id.clone();
        let lf = d.package_versions[&id].clone();
        let pkg = d.packages[&id].clone();
        (id, pkg, lf)
    }

    /// Runs the vetting check on v1 and an edited v2 (a new id, as an edited package has one).
    fn check_edited(
        edit: impl FnOnce(&mut Package),
        present_lf: Option<&str>,
    ) -> Result<(), UpgradeCheckError> {
        let (v1_id, v1, v1_lf) = main_package("upg-1.0.0.dar");
        let (_, mut v2, v2_lf) = main_package("upg-2.0.0.dar");
        edit(&mut v2);
        let lf = present_lf.unwrap_or(&v2_lf);
        let mut vetted = BTreeMap::new();
        let past = PackageSignature::from_package(&v1_id, &v1, &v1_lf).expect("v1");
        let present = PackageSignature::from_package("edited", &v2, lf).expect("v2");
        vetted.insert(v1_id, past);
        vetted.insert("edited".to_string(), present);
        validate_upgrade(
            &BTreeSet::from(["edited".to_string()]),
            &vetted,
            &BTreeMap::new(),
        )
    }

    fn reason(edit: impl FnOnce(&mut Package)) -> String {
        match check_edited(edit, None) {
            Err(UpgradeCheckError::NotValidUpgrade { reason, .. }) => reason.to_string(),
            other => panic!("expected NOT_VALID_UPGRADE_PACKAGE, got {other:?}"),
        }
    }

    fn intern(pkg: &mut Package, s: &str) -> i32 {
        pkg.interned_strings.push(s.to_string());
        i32::try_from(pkg.interned_strings.len() - 1).expect("index")
    }

    fn account_fields(pkg: &mut Package) -> &mut Vec<crate::proto::daml_lf_2::FieldWithType> {
        let names: Vec<String> = (0..pkg.interned_dotted_names.len())
            .map(|i| {
                let i = i32::try_from(i).expect("index");
                dotted_string("", pkg, i, "test").expect("name")
            })
            .collect();
        let account = pkg.modules[0]
            .data_types
            .iter_mut()
            .find(|d| names[usize::try_from(d.name_interned_dname).expect("idx")] == "Account")
            .expect("the Account record");
        match account.data_cons.as_mut() {
            Some(def_data_type::DataCons::Record(r)) => &mut r.fields,
            _ => panic!("Account is a record"),
        }
    }

    fn add_enum(pkg: &mut Package, constructors: &[&str]) {
        let name = intern(pkg, "Color");
        pkg.interned_dotted_names
            .push(crate::proto::daml_lf_2::InternedDottedName {
                segments_interned_str: vec![name],
            });
        let dname = i32::try_from(pkg.interned_dotted_names.len() - 1).expect("index");
        let cons = constructors.iter().map(|c| intern(pkg, c)).collect();
        pkg.modules[0].data_types.push(DefDataType {
            name_interned_dname: dname,
            serializable: true,
            data_cons: Some(def_data_type::DataCons::Enum(
                def_data_type::EnumConstructors {
                    constructors_interned_str: cons,
                },
            )),
            ..Default::default()
        });
    }

    #[test]
    fn the_fixture_v2_upgrades_v1_whatever_the_order_given() {
        let v1 = PackageSignature::of_dar(&dar("upg-1.0.0.dar")).expect("v1");
        let v2 = PackageSignature::of_dar(&dar("upg-2.0.0.dar")).expect("v2");
        let mut all = v2;
        all.extend(v1);
        let ids: BTreeSet<String> = all.keys().cloned().collect();
        assert_eq!(validate_upgrade(&ids, &all, &BTreeMap::new()), Ok(()));
        assert_eq!(check_edited(|_| {}, None), Ok(()));
    }

    #[test]
    fn a_removed_choice_is_refused_with_the_canton_error() {
        let (v1_id, ..) = main_package("upg-1.0.0.dar");
        let err = check_edited(
            |p| {
                let strings = p.interned_strings.clone();
                p.modules[0].templates[0].choices.retain(|c| {
                    usize::try_from(c.name_interned_str)
                        .ok()
                        .and_then(|i| strings.get(i))
                        .is_none_or(|n| n != "Bump")
                });
            },
            None,
        )
        .expect_err("refused");
        assert_eq!(err.code(), "NOT_VALID_UPGRADE_PACKAGE");
        assert_eq!(
            err.to_string(),
            format!(
                "Upgrade checks indicate that edited (upg v2.0.0) cannot be an upgrade of {v1_id} (upg v1.0.0). \
                 Reason: Choice Bump appears in package that is being upgraded, but does not appear in the upgrading package."
            )
        );
    }

    #[test]
    fn record_fields_may_only_grow_by_optional_fields_at_the_end() {
        assert_eq!(
            reason(|p| account_fields(p)[2].r#type = Some(Type {
                sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                    builtin: BuiltinType::Text as i32,
                    args: vec![],
                })),
            })),
            "The upgraded template Account has added new fields, but those fields are not Optional."
        );
        assert_eq!(
            reason(|p| account_fields(p).swap(0, 1)),
            "The upgraded template Account has changed the order of its fields - any new fields must be added at the end of the record."
        );
        assert_eq!(
            reason(|p| {
                account_fields(p).remove(1);
            }),
            "The upgraded template Account is missing some of its original fields."
        );
    }

    #[test]
    fn enums_may_only_append_constructors() {
        let check = |past: &[&str], present: &[&str]| {
            let (v1_id, mut v1, v1_lf) = main_package("upg-1.0.0.dar");
            let (_, mut v2, v2_lf) = main_package("upg-2.0.0.dar");
            add_enum(&mut v1, past);
            add_enum(&mut v2, present);
            let past = PackageSignature::from_package(&v1_id, &v1, &v1_lf).expect("v1");
            let present = PackageSignature::from_package("edited", &v2, &v2_lf).expect("v2");
            let metas =
                BTreeMap::from([(v1_id, past.meta()), ("edited".to_string(), present.meta())]);
            typecheck_upgrades(&metas, &past, &present).map_err(|e| e.to_string())
        };
        assert_eq!(check(&["Red", "Blue"], &["Red", "Blue", "Green"]), Ok(()));
        assert_eq!(
            check(&["Red", "Blue"], &["Blue", "Red"]),
            Err("The upgraded data type Color has changed the order of its variants - any new variant must be added at the end of the enum.".into())
        );
        assert_eq!(
            check(&["Red", "Blue"], &["Red"]),
            Err("The upgraded data type Color has removed an existing variant.".into())
        );
    }

    #[test]
    fn same_name_and_version_is_a_known_package_version() {
        let err = check_edited(
            |p| {
                let v = p.metadata.as_ref().expect("metadata").version_interned_str;
                p.interned_strings[usize::try_from(v).expect("idx")] = "1.0.0".into();
            },
            None,
        )
        .expect_err("refused");
        assert_eq!(err.code(), "KNOWN_PACKAGE_VERSION");
        assert!(err
            .to_string()
            .starts_with("Tried to vet two packages with the same name and version: "));
    }

    #[test]
    fn the_lf_version_may_not_go_down() {
        let (_, _, v1_lf) = main_package("upg-1.0.0.dar");
        let (v1_id, v1, _) = main_package("upg-1.0.0.dar");
        let (_, v2, v2_lf) = main_package("upg-2.0.0.dar");
        let past = PackageSignature::from_package(&v1_id, &v1, "2.dev").expect("v1");
        let present = PackageSignature::from_package("edited", &v2, &v2_lf).expect("v2");
        assert_eq!(v1_lf, v2_lf);
        assert_eq!(
            typecheck_upgrades(&BTreeMap::new(), &past, &present).map_err(|e| e.to_string()),
            Err(format!(
                "The upgraded package uses an older LF version ({v2_lf} < 2.dev)"
            ))
        );
    }

    #[test]
    fn package_versions_order_by_segment() {
        let v = |s| PackageVersion::parse(s).expect(s);
        assert!(v("1.10.0") > v("1.9.3"));
        assert!(v("1.0") < v("1.0.0"));
        assert_eq!(PackageVersion::parse("01.0"), None);
        assert_eq!(PackageVersion::parse("1..0"), None);
    }
}
