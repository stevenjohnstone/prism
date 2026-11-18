FROM aflplusplus/aflplusplus:v5.03c

ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ENV MAKEFLAGS=-j8
ENV LC_CTYPE=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
        libglib2.0-dev \
        bsdmainutils \
        libyaml-dev \
        libz-dev \
        libssl-dev \
        valgrind \
        uuid-dev \
        default-jre \
        python3 \
        unzip \
        tmux \
        clang-format \
        xxhash \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Guard g_close(task->fd, NULL) against task->fd == -1 so GLib >= 2.76 does not
# raise G_CRITICAL / SIGTRAP when halfempty cleans up already-closed task fds.
RUN git clone https://github.com/googleprojectzero/halfempty \
    && cd halfempty && sed -i 's/g_close(task->fd, NULL);/if (task->fd != -1) g_close(task->fd, NULL);/' tree.c && make && cp halfempty /usr/bin/ \
    && cd / && rm -rf halfempty

ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"

# Pin an explicit ruby/ruby mainline commit SHA (do not use a moving ref like `master`)
# so bumping this value invalidates both Make stamps and this Docker build layer.
# Run `make fuzz-docker-update` to advance to mainline HEAD, or override with RUBY_GIT_REF=...
ARG RUBY_GIT_REF=4414d3ea25fe74f06bf13370b06973544bbc1dd4
RUN apt-get update && apt-get install -y --no-install-recommends ruby \
    && git init /opt/ruby \
    && git -C /opt/ruby fetch --depth=1 https://github.com/ruby/ruby.git "${RUBY_GIT_REF}" \
    && git -C /opt/ruby checkout FETCH_HEAD \
    && cd /opt/ruby && ./autogen.sh && ./configure --disable-install-doc && make && make install \
    && apt-get purge -y ruby && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && hash -r \
    && sed -i 's|^BASERUBY = .*|BASERUBY = /usr/local/bin/ruby --disable=gems|' /opt/ruby/Makefile \
    && git config --system --add safe.directory /opt/ruby
RUN gem install rake-compiler ruby_memcheck concurrent-ruby bundler lrama-fuzz
COPY Gemfile Gemfile.lock prism.gemspec /prism/
WORKDIR /prism
RUN bundle install
USER $USERNAME


