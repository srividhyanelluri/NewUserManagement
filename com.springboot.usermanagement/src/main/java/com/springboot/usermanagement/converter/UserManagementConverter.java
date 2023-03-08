package com.springboot.usermanagement.converter;

import java.util.Map;

import org.springframework.stereotype.Service;

import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.entity.UserManagementEntity;
@Service
public class UserManagementConverter implements EntityDtoconverter<UserManagementEntity, UserManagementDto> {

	@Override
	public UserManagementEntity convertToEntity(UserManagementDto dto, Map<String, Object> propertyMap) {
		// TODO Auto-generated method stub
		UserManagementEntity Entity = new UserManagementEntity();
		Entity.setUserId(dto.getUserId());
		Entity.setFirstName(dto.getFirstName());
		Entity.setLastName(dto.getLastName());
		Entity.setEmail(dto.getEmail());
		Entity.setPassword(dto.getPassword());
		Entity.setDateOfBirth(dto.getDateOfBirth());
		Entity.setGender(dto.getGender());
		
		return Entity;
	
	}

	@Override
	public UserManagementDto convertToDto(UserManagementEntity entity, Map<String, Object> propertyMap) {
		// TODO Auto-generated method stub
		UserManagementDto dto = new UserManagementDto();
		dto.setUserId(entity.getUserId());
		dto.setFirstName(entity.getFirstName());
		dto.setLastName(entity.getLastName());
		dto.setEmail(entity.getEmail());
		dto.setPassword(entity.getPassword());
		dto.setDateOfBirth(entity.getDateOfBirth());
		dto.setGender(entity.getGender());
	
		return dto;
	}

}
