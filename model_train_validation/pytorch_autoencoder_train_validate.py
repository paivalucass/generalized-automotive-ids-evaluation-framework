# Arquivo: simple_ae_trainer.py

import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import typing

class PytorchAutoencoderTrainValidation:

    def __init__(self, model: nn.Module, learning_rate: float, batch_size: int, num_epochs: int):
        self.model = model
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.num_epochs = num_epochs
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.criterion = nn.MSELoss()

    def train_epoch(self, dataloader: DataLoader, optimizer: torch.optim.Optimizer, epoch: int) -> float:
        self.model.train()
        running_loss = 0.0
        
        for batch_idx, (data, _) in enumerate(dataloader):
            # Normalização (0-15 para 0-1)
            data = data.float().to(self.device) / 15.0 
            target = data.clone() # No autoencoder, o alvo é a própria entrada
            
            optimizer.zero_grad()
            
            out = self.model(data)
            recon = out[0] if isinstance(out, (tuple, list)) else out

            loss = self.criterion(recon, target)
            loss.backward()
            optimizer.step()
            
            running_loss += loss.item()

            if batch_idx % 50 == 0:
                print(f"Epoch: {epoch} \t Batch: {batch_idx}/{len(dataloader)} \t Loss: {loss.item():.6f}")

        return running_loss / len(dataloader)

    def execute(self, train_data: typing.List[np.ndarray]):
        """
        train_data: Lista de amostras de entrada X (apenas tráfego normal).
        """
        self.model.to(self.device)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.learning_rate)
        
        print(f"Número total de amostras de treino: {len(train_data)}")
        
        # Preparação do DataLoader (Assume que train_data é uma lista de tensores/arrays de entrada)
        # O segundo elemento do TensorDataset é um 'dummy' y, pois o AE usa (X, X)
        train_tensors = torch.stack([torch.tensor(x, dtype=torch.float) for x in train_data])
        dummy_y = torch.zeros(len(train_data))
        dataset = TensorDataset(train_tensors, dummy_y)
        
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        # Loop de Treinamento
        for epoch in range(self.num_epochs):
            avg_loss = self.train_epoch(dataloader, optimizer, epoch)
            print(f"--- Epoch {epoch+1}/{self.num_epochs} Concluída. Média de Loss: {avg_loss:.6f} ---")
        
        # Calcule e salve os erros de reconstrução no conjunto de treino completo (necessário para o threshold)
        errors_train = self.compute_reconstruction_errors(dataloader)
        print(f"Média dos erros de reconstrução no treino: {np.mean(errors_train):.6f}")
        
        # **SALVAR O MODELO AQUI**
        torch.save(self.model.state_dict(), "simple_ae_trained_model.pt")
        print("Modelo salvo como simple_ae_trained_model.pt")
        
        return errors_train

    def compute_reconstruction_errors(self, dataloader: DataLoader) -> np.ndarray:
        """Calcula o erro de reconstrução MSE por amostra."""
        self.model.eval()
        errors = []
        with torch.no_grad():
            for data, _ in dataloader:
                # Normalização
                data = data.float().to(self.device) / 15.0 
                
                out = self.model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                
                # Erro MSE por amostra (média sobre todas as dimensões da amostra)
                batch_errors = torch.mean(
                    (recon - data) ** 2,
                    dim=tuple(range(1, recon.dim()))
                ).cpu().numpy()
                errors.extend(batch_errors.tolist())
                
        return np.array(errors)