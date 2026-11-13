# OSS-Fuzz builder image for ruby/prism (mirrors test/fuzz/oss-fuzz/).
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y ruby zip
RUN git clone --depth 1 https://github.com/ruby/prism.git prism
WORKDIR prism
COPY build.sh $SRC/

