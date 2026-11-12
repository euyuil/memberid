FROM scratch
COPY --chmod=0555 memberid /usr/local/bin/memberid
COPY third_party /usr/share/memberid/third_party
COPY BUILDINFO /usr/share/memberid/BUILDINFO
LABEL org.opencontainers.image.title="MemberID" \
      org.opencontainers.image.description="Self-hosted OpenID Connect with independent organization Member identities"
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/memberid"]
CMD ["serve", "--directory", "/etc/memberid", "--listen", "0.0.0.0:8080"]
