/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

$(function() {
  var cgi_script = '/cgi-bin/aclcheck_cgi.py';

  function formatAddressAndPort(protocol, address, port) {
    if (address.indexOf(':') != -1) {
      address = '[' + address + ']';
    }
    if (protocol == 'icmp') {
      formatted = address;
    } else {
      formatted = address + '<span class="port">:' + port + '</span>';
    }
    return formatted;
  }

  function formatResults(results) {
    $('#result').empty();
    if (typeof results == 'string') {
      $('<pre/>').addClass('error').text(results).appendTo('#result');
    } else {
      $.each(results, function(index, value) {
        var table = $('<table/>').appendTo("#result");
        $('<caption/>').text(value.protocol.toUpperCase()).appendTo(table);
        var tr = $('<tr/>').appendTo(table);
        var source_address, destination_address;
        if (value.policy_file.indexOf('outbound') != -1) {
          destination_address = $('<td/>').html(formatAddressAndPort(value.protocol, value.destination_address, value.destination_port)).appendTo(tr);
          $('<td/>').addClass(value.result.indexOf('accept') != -1 ? 'accept' : 'deny').html("&#8592;").appendTo(tr);
          source_address = $('<td/>').html(formatAddressAndPort(value.protocol, value.source_address, value.source_port)).appendTo(tr);
        } else {
          source_address = $('<td/>').html(formatAddressAndPort(value.protocol, value.source_address, value.source_port)).appendTo(tr);
          $('<td/>').addClass(value.result.indexOf('accept') != -1 ? 'accept' : 'deny').html("&#8594;").appendTo(tr);
          destination_address = $('<td/>').html(formatAddressAndPort(value.protocol, value.destination_address, value.destination_port)).appendTo(tr);
        }
        $('<pre/>').text(value.result).appendTo('#result');
        $.getJSON(cgi_script, {
          action: 'reverse_dns',
          address: value.source_address
        }, function(reverse_dns_result) {
          $('<span/>').addClass('hostname').text(reverse_dns_result).appendTo(source_address);
        });
        $.getJSON(cgi_script, {
          action: 'reverse_dns',
          address: value.destination_address
        }, function(reverse_dns_result) {
          $('<span/>').addClass('hostname').text(reverse_dns_result).appendTo(destination_address);
        });
      });
    }
  }

  $.getJSON(cgi_script, {action: 'policies'}, function(data) {
    $.each(data, function(index, value) {
      $('<option/>').text(value).appendTo('#policy_file');
    });
  });

  $('#check_acl').submit(function() {
    var protocols = [];
    $('.protocols_acl:checked').each(function() {
      protocols.push($(this).val());
    });
    $.getJSON(cgi_script, {
      action: 'check_acl',
      policy_file: $('#policy_file').val(),
      protocols: protocols.join(' '),
      destination_addresses: $('#destination_addresses').val(),
      destination_ports: $('#destination_ports').val(),
      source_addresses: $('#source_addresses').val(),
      source_ports: $('#source_ports').val()
    }, function(check_acl_results) {
      formatResults(check_acl_results);
    });
    return false;
  });

  $('#check_utnet').submit(function() {
    var protocols = [];
    $('.protocols_utnet:checked').each(function() {
      protocols.push($(this).val());
    });
    $.getJSON(cgi_script, {
      action: 'check_utnet',
      protocols: protocols.join(' '),
      addresses1: $('#addresses1').val(),
      ports1: $('#ports1').val(),
      addresses2: $('#addresses2').val(),
      ports2: $('#ports2').val()
    }, function(check_utnet_results) {
      formatResults(check_utnet_results);
    });
    return false;
  });
});
