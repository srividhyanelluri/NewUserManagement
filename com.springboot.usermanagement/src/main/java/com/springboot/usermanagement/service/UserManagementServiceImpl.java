package com.springboot.usermanagement.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.springboot.usermanagement.converter.UserManagementConverter;
import com.springboot.usermanagement.dao.UserManagementRepository;
import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.entity.UserManagementEntity;

@Service
public class UserManagementServiceImpl implements UserManagementService {

	@Autowired
	private UserManagementRepository userManagementRepository;

	@Autowired
	private UserManagementConverter userManagementConverter;

	@Override
	public List<UserManagementDto> getAllDetails() {
		List<UserManagementEntity> userList = userManagementRepository.findAll();
		List<UserManagementDto> userdtoList = new ArrayList<>();

		for (UserManagementEntity entity : userList) {
			UserManagementDto dto = new UserManagementDto();
			dto = userManagementConverter.convertToDto(entity, null);
			userdtoList.add(dto);

		}
		return userdtoList;
	}

	@Override
	public UserManagementDto saveUserDetails(UserManagementDto userDto) {

		UserManagementEntity entity = new UserManagementEntity();
		entity = userManagementConverter.convertToEntity(userDto, null);
		entity = userManagementRepository.save(entity);

		UserManagementDto dto = new UserManagementDto();
		dto = userManagementConverter.convertToDto(entity, null);
		return dto;
	}

	@Override
	public UserManagementDto getUserById(Long id) {
		UserManagementEntity entity = userManagementRepository.getById(id);
		UserManagementDto dto = new UserManagementDto();
		dto = userManagementConverter.convertToDto(entity, null);
		return dto;

	}

	@Override
	public UserManagementDto updateUserDetails(Long id, UserManagementDto userDto) {

		UserManagementEntity userEntity = userManagementRepository.findById(id).get();

		if (userManagementRepository.findById(id) != null) {

			userEntity.setFirstName(userDto.getFirstName());
			userEntity.setLastName(userDto.getLastName());
			userEntity.setEmail(userDto.getEmail());
			userEntity.setPassword(userDto.getPassword());
			userEntity.setDateOfBirth(userDto.getDateOfBirth());
			userEntity.setGender(userDto.getGender());

			userManagementRepository.save(userEntity);

			UserManagementDto dto = new UserManagementDto();
			dto = userManagementConverter.convertToDto(userEntity, null);
			return dto;
			
		} else {

			userEntity = userManagementConverter.convertToEntity(userDto, null);

			userManagementRepository.save(userEntity);

			UserManagementDto dto = new UserManagementDto();
			dto = userManagementConverter.convertToDto(userEntity, null);
			return dto;
		}

	}

	@Override
	public void deleteUserById(Long id) {
			userManagementRepository.deleteById(id);		
			
	}

}
