#
# Author: Yasuhito Takamiya <yasuhito@gmail.com>
#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

require 'aruba/cucumber'

Given /^I compile "(.*?)" into "(.*?)"$/ do | c_source, executable |
  run_simple "gcc #{ c_source } #{`trema-config -c -l`} -o #{ executable }", true
end

When /^\*\*\* sleep (\d+) \*\*\*$/ do | sec |
  sleep sec.to_i
end

When /^wait until "([^"]*)" is up$/ do | process |
  nloop = 0
  pid_file = File.join(Trema.pid, "#{ process }.pid")
  loop do
    nloop += 1
    fail 'Timeout' if nloop > 60 # FIXME
    break if FileTest.exists?(pid_file) && !ps_entry_of(process).nil?
    sleep 0.1
  end
  sleep 1  # FIXME
end

Then /^([^\s]*) is terminated$/ do | name |
  ps_entry_of(name).should be_empty
end

Then /^vswitch ([^\s]*) is terminated$/ do | dpid |
  pid_file = File.join(Trema.tmp, "openflowd.#{ dpid }.pid")
  File.exist?(pid_file).should be_false
end

Then /^([^\s]*) is started$/ do | name |
  ps_entry_of(name).should_not be_empty
end

Then /^switch_manager should be killed$/ do
  IO.read(@log).should match(/^Shutting down switch_manager/)
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
