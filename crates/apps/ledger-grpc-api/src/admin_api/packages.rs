//! `com.digitalasset.canton.admin.participant.v30.PackageService` gRPC handlers (all 12 RPCs).

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use ledger_json_api::{
    v2_packages::{
        admin_get_dar, admin_get_dar_contents, admin_get_package_contents,
        admin_get_package_references, admin_remove_dar, admin_remove_package, admin_unvet_dar,
        admin_upload_dars, admin_validate_dar, admin_vet_dar, UploadDarItem,
    },
    ExecutionService,
};
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::Status;

use super::{decode_typed, encode_typed, map_admin_err};

fn pkg_desc(
    package_id: String,
    name: String,
    version: String,
    size: usize,
) -> p30::PackageDescription {
    p30::PackageDescription {
        package_id,
        name,
        version,
        uploaded_at: None,
        size: u32::try_from(size).unwrap_or(u32::MAX),
    }
}

fn dar_desc(
    main: String,
    name: String,
    version: String,
    description: String,
) -> p30::DarDescription {
    p30::DarDescription {
        main,
        name,
        version,
        description,
    }
}

/// Dispatches all 12 RPCs of `com.digitalasset.canton.admin.participant.v30.PackageService`.
pub fn handle_package_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    match method.name() {
        "ListPackages" => Some((|| {
            let req: p30::ListPackagesRequest = decode_typed(request)?;
            let limit = req.limit.max(0) as usize;
            let mut ids = ledger.package_ids();
            if limit > 0 {
                ids.truncate(limit);
            }
            let mut package_descriptions = Vec::new();
            for id in ids {
                let (name, version) = ledger.package_name_and_version(&id).unwrap_or_default();
                if !name.starts_with(&req.filter_name) {
                    continue;
                }
                let size = ledger.package_payload_size(&id);
                package_descriptions.push(pkg_desc(id, name, version, size));
            }
            Ok(vec![encode_typed(
                method,
                &p30::ListPackagesResponse {
                    package_descriptions,
                },
            )?])
        })()),
        "ListDars" => Some((|| {
            let req: p30::ListDarsRequest = decode_typed(request)?;
            let limit = req.limit.max(0) as usize;
            let mut mains = ledger.loaded_dar_descriptions();
            if limit > 0 {
                mains.truncate(limit);
            }
            let dars = mains
                .into_iter()
                .filter(|(_, name, _, _)| name.starts_with(&req.filter_name))
                .map(|(main, name, version, description)| {
                    dar_desc(main, name, version, description)
                })
                .collect();
            Ok(vec![encode_typed(method, &p30::ListDarsResponse { dars })?])
        })()),
        "UploadDar" => Some((|| {
            let req: p30::UploadDarRequest = decode_typed(request)?;
            let items: Vec<UploadDarItem<'_>> = req
                .dars
                .iter()
                .map(|d| UploadDarItem {
                    bytes: &d.bytes,
                    description: d.description.as_deref(),
                    expected_main_package_id: d.expected_main_package_id.as_deref(),
                })
                .collect();
            let dar_ids = admin_upload_dars(
                ledger,
                &items,
                req.vet_all_packages,
                req.synchronizer_id.as_deref(),
                true,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::UploadDarResponse { dar_ids },
            )?])
        })()),
        "ValidateDar" => Some((|| {
            let req: p30::ValidateDarRequest = decode_typed(request)?;
            let main_package_id =
                admin_validate_dar(ledger, &req.data, req.synchronizer_id.as_deref())
                    .map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ValidateDarResponse { main_package_id },
            )?])
        })()),
        "GetDar" => Some((|| {
            let req: p30::GetDarRequest = decode_typed(request)?;
            let (payload, name, version, description) =
                admin_get_dar(ledger, &req.main_package_id).map_err(map_admin_err)?;
            let resp = p30::GetDarResponse {
                payload,
                data: Some(dar_desc(req.main_package_id, name, version, description)),
            };
            Ok(vec![encode_typed(method, &resp)?])
        })()),
        "GetDarContents" => Some((|| {
            let req: p30::GetDarContentsRequest = decode_typed(request)?;
            let c = admin_get_dar_contents(ledger, &req.main_package_id).map_err(map_admin_err)?;
            let packages = c
                .packages
                .into_iter()
                .map(|(id, name, version, size)| pkg_desc(id, name, version, size))
                .collect();
            let resp = p30::GetDarContentsResponse {
                description: Some(dar_desc(c.main, c.name, c.version, c.description)),
                packages,
            };
            Ok(vec![encode_typed(method, &resp)?])
        })()),
        "GetPackageContents" => Some((|| {
            let req: p30::GetPackageContentsRequest = decode_typed(request)?;
            let c = admin_get_package_contents(ledger, &req.package_id).map_err(map_admin_err)?;
            let resp = p30::GetPackageContentsResponse {
                description: Some(pkg_desc(c.package_id, c.name, c.version, c.size)),
                modules: c
                    .modules
                    .into_iter()
                    .map(|name| p30::ModuleDescription { name })
                    .collect(),
                is_utility_package: c.is_utility_package,
                language_version: c.language_version,
            };
            Ok(vec![encode_typed(method, &resp)?])
        })()),
        "GetPackageReferences" => Some((|| {
            let req: p30::GetPackageReferencesRequest = decode_typed(request)?;
            let dars = admin_get_package_references(ledger, &req.package_id)
                .map_err(map_admin_err)?
                .into_iter()
                .map(|(main, name, version, description)| {
                    dar_desc(main, name, version, description)
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::GetPackageReferencesResponse { dars },
            )?])
        })()),
        "RemoveDar" => Some((|| {
            let req: p30::RemoveDarRequest = decode_typed(request)?;
            admin_remove_dar(ledger, &req.main_package_id).map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::RemoveDarResponse {})?])
        })()),
        "RemovePackage" => Some((|| {
            let req: p30::RemovePackageRequest = decode_typed(request)?;
            admin_remove_package(ledger, &req.package_id, req.force).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::RemovePackageResponse { success: Some(()) },
            )?])
        })()),
        "VetDar" => Some((|| {
            let req: p30::VetDarRequest = decode_typed(request)?;
            admin_vet_dar(ledger, &req.main_package_id, req.synchronizer_id.as_deref())
                .map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::VetDarResponse {})?])
        })()),
        "UnvetDar" => Some((|| {
            let req: p30::UnvetDarRequest = decode_typed(request)?;
            admin_unvet_dar(ledger, &req.main_package_id, req.synchronizer_id.as_deref())
                .map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::UnvetDarResponse {})?])
        })()),
        _ => None,
    }
}
