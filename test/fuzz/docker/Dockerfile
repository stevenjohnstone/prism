FROM aflplusplus/aflplusplus:v5.03c

ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ARG RUBY_VERSION=3.3.10
ENV MAKEFLAGS=-j8

RUN apt update && apt install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME


RUN wget https://cache.ruby-lang.org/pub/ruby/3.3/ruby-${RUBY_VERSION}.tar.gz -O ruby.tar.gz
RUN mkdir ruby-source && tar -xvf ruby.tar.gz -C ruby-source --strip-components=1
RUN apt update && apt -y install libyaml-dev libz-dev libssl-dev
RUN cd ruby-source && ./configure --disable-install-doc && make && make install
RUN gem install rake-compiler ruby_memcheck concurrent-ruby
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
ENV LC_CTYPE=C.UTF-8
RUN apt install -y libglib2.0-dev bsdmainutils
RUN git clone https://github.com/googleprojectzero/halfempty
# Guard g_close(task->fd, NULL) against task->fd == -1 so GLib >= 2.76 does not
# raise G_CRITICAL / SIGTRAP when halfempty cleans up already-closed task fds.
RUN cd halfempty && sed -i 's/g_close(task->fd, NULL);/if (task->fd != -1) g_close(task->fd, NULL);/' tree.c && make && cp halfempty /usr/bin/
RUN apt install -y valgrind uuid-dev default-jre python3 unzip
RUN wget https://www.antlr.org/download/antlr-4.8-complete.jar \
    && cp -f antlr-4.8-complete.jar /usr/local/lib
ARG GRAMMAR_MUTATOR_VERSION=b108ec696ad60b2ad88babace7ebda138276bde3
RUN git clone https://github.com/AFLplusplus/Grammar-Mutator \
    && cd Grammar-Mutator \
    && git checkout ${GRAMMAR_MUTATOR_VERSION} \
    && make -C third_party \
    && chown -R $USERNAME:$USERNAME /AFLplusplus/Grammar-Mutator
RUN apt install -y tmux clang-format xxhash
ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
COPY Gemfile Gemfile.lock prism.gemspec /prism/
WORKDIR /prism
RUN bundle install
USER $USERNAME


