function uuid4() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }
  return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
    s4() + '-' + s4() + s4() + s4();
}

function dismissError(errorId) {
  errorWindows = document.getElementsByClassName('modalError');
  if (errorWindows.length > 0) {
    for (i = 0; i < errorWindows.length; i++) {
      if (errorWindows[i].id == errorId)
        document.body.removeChild(errorWindows[i]);
    }
  }
  
  errorWindows = document.getElementsByClassName('modalError')
  if (errorWindows.length == 0) {
    errorOverlay = document.getElementById('errorOverlay')
    if (errorOverlay)
      document.body.removeChild(errorOverlay);
  }
}

function showError(exception) {
  errorWindow = document.createElement('div');
  errorId = uuid4();
  errorWindow.id = errorId;
  errorWindow.className = 'modalError';
  
  errorMessage = document.createElement('div');
  messageText = exception.error
  if (exception.code)
    messageText = exception.code + ": " + messageText
  errorMessage.innerHTML = messageText;

  errorWindow.appendChild(errorMessage);
  
  dismissButton = document.createElement('button');
  dismissButton.className = 'errorButton';
  dismissButton.innerHTML = 'OK';
  dismissButton.onclick = new Function("dismissError('"+errorId+"');");
  errorWindow.appendChild(dismissButton);

  document.body.appendChild(errorWindow);
  
  existingErrorOverlay = document.getElementById('errorOverlay')
  if (! existingErrorOverlay) {
    errorOverlay = document.createElement('div');
    errorOverlay.id = 'errorOverlay';
    errorOverlay.className = 'errorOverlay';
  
    document.body.appendChild(errorOverlay);
  }
}
