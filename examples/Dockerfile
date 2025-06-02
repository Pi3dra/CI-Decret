FROM debian:bullseye

ARG SNAPSHOT=20210101T024031Z
ARG KERNEL=linux-image-5.10.0-1-amd64

RUN mkdir -p /etc/apt/sources.list.d/ && \
    echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT/ testing main" > /etc/apt/sources.list.d/snapshot.list && \
    echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT/ stable main" >> /etc/apt/sources.list.d/snapshot.list && \
    echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT/ unstable main" >> /etc/apt/sources.list.d/snapshot.list

RUN apt update && \
    apt install -y "$KERNEL" initramfs-tools && \
    echo "virtiofs" >> /etc/initramfs-tools/modules && \
    echo "virtio_console" >> /etc/initramfs-tools/modules && \
    echo "RESUME=none" >/etc/initramfs-tools/conf.d/resume && \
    update-initramfs -u 

RUN apt install -y gcc git expect

RUN useradd -m -U user

USER user:user
WORKDIR /home/user

RUN git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits /home/user/exploit && \
    cd /home/user/exploit && \
    chmod +x compile.sh && \
    ./compile.sh && \
    cp exploit* /home/user && \
    rm -rf /home/user/exploit
