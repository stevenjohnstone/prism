FROM aflplusplus/aflplusplus:v5.03c

ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ENV MAKEFLAGS=-j8
ARG RUBY_VERSION=4.0.9

RUN apt update && apt install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME


ENV LC_CTYPE=C.UTF-8
RUN apt install -y libglib2.0-dev bsdmainutils
RUN wget https://cache.ruby-lang.org/pub/ruby/4.0/ruby-${RUBY_VERSION}.tar.gz -O ruby.tar.gz
RUN mkdir /opt/ruby && tar -xvf ruby.tar.gz -C /opt/ruby --strip-components=1
RUN apt -y install libyaml-dev libz-dev libssl-dev
RUN cd /opt/ruby && ./configure --disable-install-doc && make && make install
RUN gem install rake-compiler ruby_memcheck concurrent-ruby bundler lrama-fuzz
# Guard g_close(task->fd, NULL) against task->fd == -1 so GLib >= 2.76 does not
# raise G_CRITICAL / SIGTRAP when halfempty cleans up already-closed task fds.
RUN git clone https://github.com/googleprojectzero/halfempty
RUN cd halfempty && sed -i 's/g_close(task->fd, NULL);/if (task->fd != -1) g_close(task->fd, NULL);/' tree.c && make && cp halfempty /usr/bin/
RUN apt install -y valgrind uuid-dev default-jre python3 unzip
RUN apt install -y tmux clang-format xxhash
ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
COPY Gemfile Gemfile.lock prism.gemspec /prism/
WORKDIR /prism
RUN bundle install
USER $USERNAME


