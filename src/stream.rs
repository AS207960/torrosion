use crate::cell;

pub struct Stream {
    stream_id: u16,
    pub(crate) circuit_end: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) command_tx: tokio_util::sync::PollSender<StreamCommand>,
    command_rx: tokio::sync::mpsc::Receiver<StreamCommand>,
    data_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    data_tx: tokio_util::sync::PollSender<Vec<u8>>,
    read_buf: Vec<u8>,
    end_sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct StreamCommand {
    pub node: usize,
    pub command: cell::RelayCommand,
}

impl Stream {
    pub(crate) fn new(
        identity: crate::RsaIdentity, stream_id: u16, circuit_id: u32,
        command_tx: tokio::sync::mpsc::Sender<StreamCommand>,
        command_rx: tokio::sync::mpsc::Receiver<StreamCommand>
    ) -> Self {
        let (data_in_tx, data_in_rx) = tokio::sync::mpsc::channel(10);
        let (data_out_tx, data_out_rx) = tokio::sync::mpsc::channel(10);
        let (command_in_tx, command_in_rx) = tokio::sync::mpsc::channel(10);
        let end_sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let circuit_end = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        Self::run(
            identity, stream_id, circuit_id,
            circuit_end.clone(), command_rx, command_in_tx,
            command_tx.clone(),
            data_in_tx, data_out_rx,
            end_sent.clone()
        );

        Stream {
            stream_id,
            circuit_end,
            command_tx: tokio_util::sync::PollSender::new(command_tx),
            command_rx: command_in_rx,
            data_rx: data_in_rx,
            data_tx: tokio_util::sync::PollSender::new(data_out_tx),
            read_buf: Vec::new(),
            end_sent,
        }
    }

    fn run(
        identity: crate::RsaIdentity,
        stream_id: u16, circuit_id: u32,
        circuit_end: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        mut command_in_rx: tokio::sync::mpsc::Receiver<StreamCommand>,
        command_in_tx: tokio::sync::mpsc::Sender<StreamCommand>,
        command_out_tx: tokio::sync::mpsc::Sender<StreamCommand>,
        data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        mut data_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        end_sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        tokio::task::spawn(async move {
            let mut package_window = crate::STREAM_WINDOW_INITIAL;
            let mut deliver_window = crate::STREAM_WINDOW_INITIAL;

            macro_rules! process_command {
                ($ic:expr) => {
                    match $ic {
                        Some(command) => {
                            match command.command {
                                cell::RelayCommand::Data(d) => {
                                    deliver_window -= 1;
                                    match data_tx.send(d).await {
                                        Ok(_) => (),
                                        Err(_) => return
                                    }

                                    if deliver_window <= (crate::STREAM_WINDOW_INITIAL - crate::STREAM_WINDOW_INCREMENT) {
                                        let pending_data = data_tx.max_capacity() - data_tx.capacity();
                                        if pending_data < 10 {
                                            deliver_window += crate::STREAM_WINDOW_INCREMENT;
                                            match command_out_tx.send(StreamCommand {
                                                node: circuit_end.load(std::sync::atomic::Ordering::Relaxed),
                                                command: cell::RelayCommand::SendMe(cell::RelaySendMe {
                                                    version: 0,
                                                    data: None
                                                })
                                            }).await {
                                                Ok(_) => (),
                                                Err(_) => return
                                            }
                                        }
                                    }
                                    if deliver_window < 0 {
                                        return;
                                    }
                                }
                                cell::RelayCommand::SendMe(_) => {
                                    package_window += crate::STREAM_WINDOW_INCREMENT;
                                }
                                cell::RelayCommand::End(e) => {
                                    debug!("{}: circuit {}, stream {} closed ({:?})", identity, circuit_id, stream_id, e.reason);
                                    return;
                                }
                                _ => match command_in_tx.send(command).await {
                                    Ok(_) => (),
                                    Err(_) => return
                                }
                            }
                        },
                        None => return
                    }
                }
            }

            macro_rules! process_data {
                ($id:expr) => {
                    match $id {
                        Some(data) => {
                            match command_out_tx.send(StreamCommand {
                                node: circuit_end.load(std::sync::atomic::Ordering::Relaxed),
                                command: cell::RelayCommand::Data(data)
                            }).await {
                                Ok(_) => (),
                                Err(_) => return
                            }
                            package_window -= 1;
                        },
                        None => {
                            if end_sent.load(std::sync::atomic::Ordering::Relaxed) {
                                return;
                            }
                            end_sent.store(true, std::sync::atomic::Ordering::Relaxed);
                            let _ = command_out_tx.send(StreamCommand {
                                node: circuit_end.load(std::sync::atomic::Ordering::Relaxed),
                                command: cell::RelayCommand::End(cell::RelayEnd {
                                    reason: cell::EndReason::Misc,
                                    addr: None,
                                    ttl: None,
                                })
                            }).await;
                            return;
                        }
                    }
                }
            }

            loop {
                if package_window > 0 {
                    tokio::select! {
                        ic = command_in_rx.recv() => {
                            process_command!(ic);
                        }
                        id = data_rx.recv() => {
                            process_data!(id);
                        }
                    }
                } else {
                    let ic = command_in_rx.recv().await;
                    process_command!(ic);
                }
            }
        });
    }

    pub fn get_stream_id(&self) -> u16 {
        self.stream_id
    }

    pub(crate) async fn recv_command(&mut self) -> std::io::Result<StreamCommand> {
        match self.command_rx.recv().await {
            Some(command) => Ok(command),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset, "stream closed",
            )),
        }
    }
}

impl hyper::client::connect::Connection for Stream {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
            .proxy(false)
    }
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let amt = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..amt]);
            self.read_buf.drain(..amt);
            return std::task::Poll::Ready(Ok(()));
        }

        let data = match self.data_rx.poll_recv(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Some(data)) => data,
        };
        let amt = std::cmp::min(data.len(), buf.remaining());
        let (a, b) = data.split_at(amt);
        buf.put_slice(a);
        self.read_buf.extend_from_slice(b);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8]
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.data_tx.poll_reserve(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => {},
            std::task::Poll::Ready(Err(_)) => return std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream closed")
            )),
        }
        let data = buf.iter().take(crate::MAX_RELAY_DATA_LEN).map(|d| *d).collect::<Vec<u8>>();
        let len = data.len();
        match self.data_tx.send_item(data) {
            Ok(()) => {},
            Err(_) => return std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream closed")
            ))
        }
        std::task::Poll::Ready(Ok(len))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.command_tx.poll_reserve(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => {},
            std::task::Poll::Ready(Err(_)) => return std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream closed")
            )),
        }
        self.end_sent.store(true, std::sync::atomic::Ordering::Relaxed);
        let cmd = StreamCommand {
            node: self.circuit_end.load(std::sync::atomic::Ordering::Relaxed),
            command: cell::RelayCommand::End(cell::RelayEnd {
                reason: cell::EndReason::Misc,
                addr: None,
                ttl: None,
            })
        };
        match self.command_tx.send_item(cmd) {
            Ok(()) => {},
            Err(_) => return std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream closed")
            ))
        }
        std::task::Poll::Ready(Ok(()))
    }
}