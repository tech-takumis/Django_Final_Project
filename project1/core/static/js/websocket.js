document.addEventListener('DOMContentLoaded', function() {
   const accessToken = localStorage.getItem('access_token');
   if (!accessToken) {
      console.error("Access token not found");
   }
  const socket = new WebSocket(`ws://localhost:8001/api/ws/transactions/?token=${accessToken}`);
     socket.onopen = (event) => {
         console.log("WebSocket connection established.");
         };
     socket.onmessage = (event) => {
        const data = JSON.parse(event.data)
          console.log("Receive data from websocket: ",data)
         // Create a new notification div
         const notificationDiv = document.createElement('div');
         notificationDiv.classList.add('fixed', 'bottom-4', 'left-4', 'bg-emerald-600','text-white','p-4','rounded-md');
         notificationDiv.textContent = data.message;

         // Append the notification div to the body
         document.body.appendChild(notificationDiv);

         // Set a timeout to remove the notification after a few seconds (e.g., 5 seconds)
           setTimeout(() => {
               if(notificationDiv && notificationDiv.parentNode){
                  notificationDiv.parentNode.removeChild(notificationDiv);
               }
             }, 5000);
          const userId = localStorage.getItem('user_id');
          if(data.sender && data.amount && data.receiver_id == userId){
             let bankAccount = localStorage.getItem('bank_account')
             bankAccount = JSON.parse(bankAccount);
             bankAccount.balance = (parseFloat(bankAccount.balance) + parseFloat(data.amount)).toFixed(2)
             localStorage.setItem('bank_account',JSON.stringify(bankAccount));
              const balanceElement = document.getElementById('balance');
              if(balanceElement){
                    balanceElement.textContent = parseFloat(bankAccount.balance).toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2 });
             }

           }
       };

     socket.onerror = (event) => {
          console.error('WebSocket error:', event);
     };
      socket.onclose = (event) => {
           console.log("WebSocket connection closed.");
       };
    });