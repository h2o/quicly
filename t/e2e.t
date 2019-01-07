#! /usr/bin/perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);

$ENV{BINARY_DIR} ||= ".";
my $cli = "$ENV{BINARY_DIR}/cli";
my $port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $tempdir = tempdir(CLEANUP => 1);

subtest "hello" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
};

done_testing;

sub spawn_server {
    my @cmd = ($cli, "-k", "t/assets/server.key", "-c", "t/assets/server.crt", "127.0.0.1", $port);
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        exec @cmd;
        die "failed to exec $cmd[0]:$?";
    }
    while (`netstat -na` !~ /^udp.*\s127\.0\.0\.1[\.:]$port\s/m) {
        if (waitpid($pid, WNOHANG) == $pid) {
            die "failed to launch server";
        }
        sleep 0.1;
    }
    return scope_guard(sub {
        kill 9, $pid;
        while (waitpid($pid, 0) != $pid) {}
    });
}

sub slurp_file {
    my $fn = shift;
    open my $fh, "<", $fn
        or die "failed to open file:$fn:$!";
    do {
        local $/;
        <$fh>;
    };
}
