use crate::Result;

/// Boundary seam for write/fsync/publication crash-fault tests.
pub(crate) trait Publication {
    fn write_stage(&mut self, bytes: &[u8]) -> Result<()>;
    fn sync_stage(&mut self) -> Result<()>;
    fn publish_noreplace(&mut self) -> Result<()>;
    fn sync_directory(&mut self) -> Result<()>;
}

pub(crate) fn commit(publication: &mut impl Publication, bytes: &[u8]) -> Result<()> {
    publication.write_stage(bytes)?;
    publication.sync_stage()?;
    publication.publish_noreplace()?;
    publication.sync_directory()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    struct Crash {
        boundary: usize,
        step: usize,
        stage: Vec<u8>,
        published: Option<Vec<u8>>,
        synced: bool,
    }
    impl Crash {
        fn fault(&mut self) -> Result<()> {
            self.step += 1;
            if self.step == self.boundary {
                Err(Error::Refused)
            } else {
                Ok(())
            }
        }
    }
    impl Publication for Crash {
        fn write_stage(&mut self, bytes: &[u8]) -> Result<()> {
            self.stage.extend_from_slice(&bytes[..bytes.len() / 2]);
            self.fault()?;
            self.stage = bytes.to_vec();
            Ok(())
        }
        fn sync_stage(&mut self) -> Result<()> {
            self.fault()?;
            self.synced = true;
            Ok(())
        }
        fn publish_noreplace(&mut self) -> Result<()> {
            self.fault()?;
            assert!(self.synced);
            if self.published.is_some() {
                return Err(Error::Refused);
            }
            self.published = Some(self.stage.clone());
            Ok(())
        }
        fn sync_directory(&mut self) -> Result<()> {
            self.fault()
        }
    }
    #[test]
    fn faults_never_expose_partial_records_or_replace_prior_authority() {
        for boundary in 1..=5 {
            let mut crash = Crash {
                boundary,
                step: 0,
                stage: Vec::new(),
                published: None,
                synced: false,
            };
            let result = commit(&mut crash, b"complete-record");
            assert_eq!(result.is_ok(), boundary == 5);
            if boundary <= 3 {
                assert!(crash.published.is_none());
            }
            if let Some(record) = crash.published {
                assert_eq!(record, b"complete-record");
            }
        }
        let mut collision = Crash {
            boundary: 5,
            step: 0,
            stage: Vec::new(),
            published: Some(b"prior-record".to_vec()),
            synced: false,
        };
        assert!(commit(&mut collision, b"new-record").is_err());
        assert_eq!(collision.published.unwrap(), b"prior-record");
    }
    #[cfg(unix)]
    #[test]
    fn native_disk_faults_keep_partial_staging_out_of_published_namespace() {
        use std::fs::{self, File};
        use std::io::Write;
        struct Disk {
            root: tempfile::TempDir,
            stage: File,
            step: usize,
            boundary: usize,
        }
        impl Disk {
            fn fault(&mut self) -> Result<()> {
                self.step += 1;
                if self.step == self.boundary {
                    Err(Error::Refused)
                } else {
                    Ok(())
                }
            }
        }
        impl Publication for Disk {
            fn write_stage(&mut self, bytes: &[u8]) -> Result<()> {
                self.stage.write_all(&bytes[..bytes.len() / 2])?;
                self.fault()?;
                self.stage.write_all(&bytes[bytes.len() / 2..])?;
                Ok(())
            }
            fn sync_stage(&mut self) -> Result<()> {
                self.fault()?;
                self.stage.sync_all()?;
                Ok(())
            }
            fn publish_noreplace(&mut self) -> Result<()> {
                self.fault()?;
                // Native analogue of linkat's no-replace publication. This
                // tests real file effects, not Linux O_TMPFILE or root trust.
                fs::hard_link(
                    self.root.path().join("stage"),
                    self.root.path().join("published"),
                )?;
                Ok(())
            }
            fn sync_directory(&mut self) -> Result<()> {
                self.fault()?;
                File::open(self.root.path())?.sync_all()?;
                Ok(())
            }
        }
        let fixture = |boundary| {
            let root = tempfile::tempdir().unwrap();
            let stage = File::create_new(root.path().join("stage")).unwrap();
            Disk {
                root,
                stage,
                step: 0,
                boundary,
            }
        };
        for boundary in 1..=5 {
            let mut disk = fixture(boundary);
            assert_eq!(commit(&mut disk, b"complete-record").is_ok(), boundary == 5);
            let published = disk.root.path().join("published");
            if boundary <= 3 {
                assert!(!published.exists());
            } else {
                assert_eq!(fs::read(published).unwrap(), b"complete-record");
            }
        }
        let mut disk = fixture(5);
        fs::write(disk.root.path().join("published"), b"prior-record").unwrap();
        assert!(commit(&mut disk, b"new-record").is_err());
        assert_eq!(
            fs::read(disk.root.path().join("published")).unwrap(),
            b"prior-record"
        );
    }
}
