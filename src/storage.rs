use tokio::io::{AsyncRead, AsyncWriteExt};

pub(crate) struct SavingReader<R: Send> {
    inner: R,
    buf: Vec<u8>
}

impl<R: Send> SavingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new()
        }
    }

    pub(crate) fn buf(&self) -> &[u8] {
        &self.buf
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for SavingReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut s = vec![0; buf.remaining()];
        let mut s_buf = tokio::io::ReadBuf::new(&mut s);
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut s_buf) {
            std::task::Poll::Ready(Ok(())) => {
                self.buf.extend_from_slice(s_buf.filled());
                buf.put_slice(s_buf.filled());
                std::task::Poll::Ready(Ok(()))
            },
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

pub trait Storage {
    fn save_consensus<'a>(&'a self, consensus: &'a [u8]) -> impl futures::Future<Output = std::io::Result<()>> + Send + 'a;
    fn load_consensus<'a>(&'a self) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a;

    fn save_dir_key_certificate<'a>(&'a self, identity: crate::RsaIdentity, cert: &'a [u8]) -> impl futures::Future<Output = std::io::Result<()>> + Send + 'a;
    fn load_dir_key_certificate<'a>(&'a self, identity: crate::RsaIdentity) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a;

    fn save_server_descriptor<'a>(&'a self, identity: &'a crate::RsaIdentity, digest: &[u8], descriptor: &'a [u8]) -> impl futures::Future<Output = std::io::Result<()>> + Send + 'a;
    fn load_server_descriptor<'a>(&'a self, identity: &'a crate::RsaIdentity, digest: &[u8]) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a;
}

pub struct FileStorage {
    root: std::path::PathBuf,
}

impl FileStorage {
    pub async fn new<P: AsRef<std::path::Path>>(root: P) -> std::io::Result<Self> {
        let p = root.as_ref().to_path_buf();
        let p1 = p.join("dir-key-certificate");
        let p2 = p.join("server-descriptor");

        if !p.exists() {
            tokio::fs::create_dir_all(&p).await?;
        }
        if !p1.exists() {
            tokio::fs::create_dir(&p1).await?;
        }
        if !p2.exists() {
            tokio::fs::create_dir(&p2).await?;
        }

        Ok(Self {
            root: p
        })
    }
}

impl Storage for FileStorage {
    fn save_consensus<'a>(&'a self, consensus: &'a [u8]) -> impl futures::Future<Output = Result<(), std::io::Error>> + Send + 'a {
        async {
            let mut f = tokio::fs::File::create(self.root.join("consensus")).await?;
            f.write_all(consensus).await?;
            Ok(())
        }
    }

    fn load_consensus<'a>(&'a self) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a {
        async {
            let f = tokio::fs::File::open(self.root.join("consensus")).await?;
            Ok(f)
        }
    }

    fn save_dir_key_certificate<'a>(&'a self, identity: crate::RsaIdentity, cert: &'a [u8]) -> impl futures::Future<Output = std::io::Result<()>> + Send + 'a {
        async move {
            let mut p = self.root.join("dir-key-certificate");
            p.push(identity.to_string());
            let mut f = tokio::fs::File::create(p).await?;
            f.write_all(cert).await?;
            Ok(())
        }
    }

   fn load_dir_key_certificate<'a>(&'a self, identity: crate::RsaIdentity) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a {
       async move {
           let mut p = self.root.join("dir-key-certificate");
           p.push(identity.to_string());
           let f = tokio::fs::File::open(p).await?;
           Ok(f)
       }
    }

    fn save_server_descriptor<'a>(&'a self, identity: &'a crate::RsaIdentity, digest: &[u8], descriptor: &'a [u8]) -> impl futures::Future<Output = std::io::Result<()>> + Send + 'a {
        let digest = hex::encode(digest);
        async move {
            let mut p = self.root.join("server-descriptor");
            p.push(identity.to_string());
            if tokio::fs::metadata(&p).await.is_ok() {
                tokio::fs::remove_dir_all(&p).await?;
            }
            tokio::fs::create_dir(&p).await?;
            p.push(digest);
            let mut f = tokio::fs::File::create(p).await?;
            f.write_all(descriptor).await?;
            Ok(())
        }
    }

    fn load_server_descriptor<'a>(&'a self, identity: &'a crate::RsaIdentity, digest: &[u8]) -> impl futures::Future<Output = std::io::Result<impl AsyncRead + Unpin + Send>> + Send + 'a {
        let digest = hex::encode(digest);
        async move {
            let mut p = self.root.join("server-descriptor");
            p.push(identity.to_string());
            p.push(digest);
            let f = tokio::fs::File::open(p).await?;
            Ok(f)
        }
    }
}